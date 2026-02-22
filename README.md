# BF Chat

A 1:1 chat application where every message is encoded and decoded by a Brainfuck interpreter.

The networking layer (TCP sockets, threading) is Python. Everything else, encoding, decoding, length computation, and even the startup banner, is done by running Brainfuck programs through an embedded interpreter.


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
