#!/usr/bin/env python3
"""
BF Chat - 1:1 chat application in Brainfuck

Message encoding/decoding: Brainfuck interpreter
Networking: Python (socket + threading)

Usage:
  Open two terminals:
  Terminal 1: python3 bf_chat.py server
  Terminal 2: python3 bf_chat.py client
  Type a message in one terminal and see it appear in the other.

  Demo:
  Terminal 3: python3 bf_chat.py demo

  Other commands:
  /quit: Exit the chat
  /bf: Show the Brainfuck programs used for encoding/decoding
  /run <code>: Run arbitrary Brainfuck

How it works:
  1) Each outgoing message is Caesar-cipher shifted by +3 using a generated BF program.
  2) Each incoming message is decoded (shift -3) using another generated BF program.
  3) A BF program computes message length for framing: [1-byte length][encoded payload].
  4) A BF program generates the chat banner string.
"""

import socket
import threading
import sys

MAX_MSG_BYTES = 255  # BF length counter uses a single byte (0-255)


class BrainfuckVM:
    """
    A full Brainfuck interpreter with input/output support.
    Memory: 30,000 cells (standard). Cells wrap at 256.
    """

    def __init__(self, tape_size: int = 30000):
        self.tape_size = tape_size

    def execute(self, code: str, input_bytes: bytes = b"") -> bytes:
        """Run a BF program and return the output as bytes."""
        code = "".join(c for c in code if c in "+-<>.,[]")

        jumps: dict[int, int] = {}
        stack: list[int] = []
        for i, ch in enumerate(code):
            if ch == "[":
                stack.append(i)
            elif ch == "]":
                if not stack:
                    raise SyntaxError(f"Unmatched ']' at position {i}")
                j = stack.pop()
                jumps[j] = i
                jumps[i] = j
        if stack:
            raise SyntaxError(f"Unmatched '[' at position {stack[-1]}")

        tape = bytearray(self.tape_size)
        dp = 0
        ip = 0
        inp_idx = 0
        output = bytearray()

        while ip < len(code):
            cmd = code[ip]
            if cmd == "+":
                tape[dp] = (tape[dp] + 1) & 0xFF
            elif cmd == "-":
                tape[dp] = (tape[dp] - 1) & 0xFF
            elif cmd == ">":
                dp += 1
                if dp >= self.tape_size:
                    dp = 0
            elif cmd == "<":
                dp -= 1
                if dp < 0:
                    dp = self.tape_size - 1
            elif cmd == ".":
                output.append(tape[dp])
            elif cmd == ",":
                if inp_idx < len(input_bytes):
                    tape[dp] = input_bytes[inp_idx]
                    inp_idx += 1
                else:
                    tape[dp] = 0  # EOF -> 0
            elif cmd == "[":
                if tape[dp] == 0:
                    ip = jumps[ip]
            elif cmd == "]":
                if tape[dp] != 0:
                    ip = jumps[ip]
            ip += 1

        return bytes(output)


class BFProgramFactory:
    """Generates Brainfuck programs for various chat operations."""

    @staticmethod
    def caesar_encode(shift: int = 3) -> str:
        """
        Read input byte-by-byte, add `shift` to each byte, output it.
        Stops when input is exhausted (cell == 0 after read).
        """
        plus = "+" * shift
        return f",[{plus}.,]"

    @staticmethod
    def caesar_decode(shift: int = 3) -> str:
        """Read input byte-by-byte, subtract `shift` from each byte, output it."""
        minus = "-" * shift
        return f",[{minus}.,]"

    @staticmethod
    def generate_string(s: str) -> str:
        """
        Output a constant string.
        Uses cell 0 as a working register and emits +/- differences per char.
        """
        code = []
        current = 0
        for ch in s:
            target = ord(ch)
            diff = target - current
            if diff >= 0:
                code.append("+" * diff)
            else:
                code.append("-" * abs(diff))
            code.append(".")
            current = target
        return "".join(code)

    @staticmethod
    def compute_length() -> str:
        """
        Read input and output the count as a single byte (for messages up to 255 bytes).
        cell[0] = counter, cell[1] = input buffer
        """
        return ">,[ <+> ,]<."

    @staticmethod
    def xor_with_key(key_byte: int) -> str:
        """
        Demo "extra layer" (not true XOR here): add key and wrap.
        """
        plus = "+" * key_byte
        return f",[{plus}.,]"


class BFChatProtocol:
    """
    Wire protocol for BF Chat.

    Frame format: [1-byte length] [encoded payload]
    - Length computed by BF.
    - Payload Caesar-encoded (+3) by BF.
    - Decoding reverses Caesar shift.
    """

    SHIFT = 3

    def __init__(self):
        self.vm = BrainfuckVM()
        self.factory = BFProgramFactory()

        self.encode_prog = self.factory.caesar_encode(self.SHIFT)
        self.decode_prog = self.factory.caesar_decode(self.SHIFT)
        self.length_prog = self.factory.compute_length()

    def encode_message(self, text: str) -> bytes:
        """Encode a chat message using Brainfuck."""
        raw = text.encode("utf-8")

        length_byte = self.vm.execute(self.length_prog, raw)
        if not length_byte:
            return b"\x00"

        encoded_payload = self.vm.execute(self.encode_prog, raw)
        return length_byte + encoded_payload

    def decode_message(self, data: bytes) -> str:
        """Decode a chat message using Brainfuck."""
        if len(data) < 1:
            return ""

        payload = data[1:]
        if not payload:
            return ""

        decoded = self.vm.execute(self.decode_prog, payload)
        return decoded.decode("utf-8", errors="replace")

    def generate_banner(self, role: str) -> str:
        """Use BF to generate the connection banner string."""
        banner_text = f"=== BF Chat [{role}] connected ==="
        prog = self.factory.generate_string(banner_text)
        result = self.vm.execute(prog)
        return result.decode("utf-8", errors="replace")


class BFChatNode:
    """
    A chat node that can act as either server or client.
    Handles sending/receiving with BF-encoded messages.
    """

    def __init__(self, role: str):
        self.role = role  # "server" or "client"
        self.protocol = BFChatProtocol()
        self.sock: socket.socket | None = None
        self.conn: socket.socket | None = None
        self.running = False
        self.peer_name = "Server" if role == "client" else "Client"
        self.my_name = role.capitalize()

    def _print_bf_info(self):
        """Print info about the BF programs being used."""
        p = self.protocol
        print("\nBrainfuck programs loaded:")
        print(f"  Encoder (Caesar +{p.SHIFT}): {p.encode_prog}")
        print(f"  Decoder (Caesar -{p.SHIFT}): {p.decode_prog}")
        print(f"  Length counter: {p.length_prog}\n")

    def _recv_message(self, sock: socket.socket) -> str | None:
        """Receive and BF-decode a single framed message."""
        try:
            header = sock.recv(1)
            if not header:
                return None

            msg_len = header[0]
            if msg_len == 0:
                return ""

            payload = b""
            while len(payload) < msg_len:
                chunk = sock.recv(msg_len - len(payload))
                if not chunk:
                    return None
                payload += chunk

            return self.protocol.decode_message(header + payload)

        except (ConnectionResetError, OSError):
            return None

    def _send_message(self, sock: socket.socket, text: str):
        """BF-encode and send a message."""
        frame = self.protocol.encode_message(text)
        sock.sendall(frame)

    def _receive_loop(self, sock: socket.socket):
        """Background thread: receive and display incoming messages."""
        while self.running:
            msg = self._recv_message(sock)
            if msg is None:
                if self.running:
                    print(f"\n[!] {self.peer_name} disconnected.")
                    self.running = False
                break

            print(f"\r\033[K\033[1;36m{self.peer_name}\033[0m: {msg}")
            print(f"\033[1;33m{self.my_name}\033[0m: ", end="", flush=True)

    def _send_loop(self, sock: socket.socket):
        """Main thread: read user input and send BF-encoded messages."""
        print(f"\033[1;33m{self.my_name}\033[0m: ", end="", flush=True)
        while self.running:
            try:
                text = input()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Exiting...")
                self.running = False
                break

            if text.lower() in ("/quit", "/exit", "/q"):
                print("[!] Closing chat...")
                self.running = False
                break

            if text.lower() == "/bf":
                self._print_bf_info()
                print(f"\033[1;33m{self.my_name}\033[0m: ", end="", flush=True)
                continue

            if text.lower().startswith("/run "):
                bf_code = text[5:]
                try:
                    result = self.protocol.vm.execute(bf_code)
                    print(f"  [BF output] {result!r}")
                except Exception as e:
                    print(f"  [BF error] {e}")
                print(f"\033[1;33m{self.my_name}\033[0m: ", end="", flush=True)
                continue

            if text.strip():
                raw = text.encode("utf-8")
                if len(raw) > MAX_MSG_BYTES:
                    text = raw[:MAX_MSG_BYTES].decode("utf-8", errors="ignore")
                    print(f"[!] Message truncated to {MAX_MSG_BYTES} bytes.")
                self._send_message(sock, text)
                print(f"\033[1;33m{self.my_name}\033[0m: ", end="", flush=True)

    def run_server(self, host: str = "0.0.0.0", port: int = 9999):
        """Start the server and wait for one client to connect."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(1)

        print("BF Chat Server Starting...")
        print(f"Listening on {host}:{port}")
        self._print_bf_info()

        wait_prog = BFProgramFactory.generate_string("Waiting for client...")
        wait_msg = self.protocol.vm.execute(wait_prog).decode()
        print(f"[BF says] {wait_msg}")

        self.conn, addr = self.sock.accept()
        self.running = True

        banner = self.protocol.generate_banner("Server")
        print(f"\n{banner}")
        print(f"[+] Client connected from {addr[0]}:{addr[1]}")
        print("[*] Commands: /quit, /bf, /run <code>\n")

        recv_thread = threading.Thread(target=self._receive_loop, args=(self.conn,), daemon=True)
        recv_thread.start()
        self._send_loop(self.conn)

        self._cleanup()

    def run_client(self, host: str = "127.0.0.1", port: int = 9999):
        """Connect to a server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("BF Chat Client Starting...")
        print(f"Connecting to {host}:{port}")
        self._print_bf_info()

        try:
            self.sock.connect((host, port))
        except ConnectionRefusedError:
            print("[!] Connection refused. Is the server running?")
            return

        self.running = True

        banner = self.protocol.generate_banner("Client")
        print(f"\n{banner}")
        print(f"[+] Connected to server at {host}:{port}")
        print("[*] Commands: /quit, /bf, /run <code>\n")

        recv_thread = threading.Thread(target=self._receive_loop, args=(self.sock,), daemon=True)
        recv_thread.start()
        self._send_loop(self.sock)

        self._cleanup()

    def _cleanup(self):
        """Close all sockets."""
        self.running = False
        if self.conn:
            try:
                self.conn.close()
            except OSError:
                pass
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        print("[*] Chat ended. Goodbye!")


def run_demo():
    """Run a self-test demonstrating BF encoding/decoding."""
    print("BF Chat — Brainfuck Engine Demo\n")

    vm = BrainfuckVM()
    factory = BFProgramFactory()
    proto = BFChatProtocol()

    print("1) Generating 'Hello!' using Brainfuck...")
    prog = factory.generate_string("Hello!")
    result = vm.execute(prog)
    print(f"   BF program length: {len(prog)} chars")
    print(f"   Output: {result.decode()}\n")

    test_msg = "Hello, Brainfuck Chat!"
    print(f"2) Encoding message: '{test_msg}'")

    encoded = vm.execute(factory.caesar_encode(3), test_msg.encode())
    print(f"   Encoded bytes: {encoded.hex()}")
    print(f"   Encoded repr:  {encoded!r}")

    decoded = vm.execute(factory.caesar_decode(3), encoded)
    print(f"   Decoded: '{decoded.decode()}'\n")

    print(f"3) Full protocol round-trip: '{test_msg}'")
    frame = proto.encode_message(test_msg)
    print(f"   Wire frame ({len(frame)} bytes): {frame.hex()}")
    print(f"   Length byte: {frame[0]} (computed by BF)")

    restored = proto.decode_message(frame)
    print(f"   Restored: '{restored}'")
    print(f"   Match: {'✓' if restored == test_msg else '✗'}\n")

    print("4) BF-generated banner:")
    banner = proto.generate_banner("Demo")
    print(f"   {banner}\n")

    print("5) BF length computation:")
    for s in ["Hi", "Hello World", "Brainfuck!"]:
        length = vm.execute(factory.compute_length(), s.encode())
        print(f"   '{s}' -> length byte = {length[0]} (actual: {len(s)})")

    print("\nAll Brainfuck engines operational. Ready to chat!")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} server [host] [port]  - Start chat server")
        print(f"  {sys.argv[0]} client [host] [port]  - Connect to server")
        print(f"  {sys.argv[0]} demo                  - Run BF engine demo")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "demo":
        run_demo()
    elif mode == "server":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
        node = BFChatNode("server")
        node.run_server(host, port)
    elif mode == "client":
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
        node = BFChatNode("client")
        node.run_client(host, port)
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()