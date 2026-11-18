PYTHON TCP CLIENT/SERVER PROJECT - Communication Technology
===========================================================
Requirements: Python 3.8+ (standard library only, no pip install).

FILES
  config.py     shared settings (HOST, PORT, chunk size, folders)
  protocol.py   message format, SHA-256 helper, send/receive helpers
  server.py     the TCP server (one thread per client)
  client.py     command-line client
  server_files/ files the server shares (put demo files here)
  downloads/    where the client saves downloaded files
  server.log    created automatically by the server

HOW TO RUN
1) Put all devices on the same network (Wi-Fi/LAN). Allow Python through the
   server PC's firewall (or open TCP port 5000).
2) On the SERVER device:
       python server.py
   It prints its IP and port, e.g.  IP: 192.168.1.10   Port: 5000
3) On each CLIENT device/window (use the server's IP, not 127.0.0.1):
       python client.py 192.168.1.10
   (Same PC test: python client.py 127.0.0.1)
   Enter a unique username. A duplicate name is rejected and you can retry.

CLIENT COMMANDS
  users                 list online users
  list                  list files on the server
  upload <path>         upload a file (SHA-256 checked on both sides)
  download <filename>   download a file into downloads/ (SHA-256 checked)
  run <COMMAND>         approved server commands only:
                        TIME, HOSTNAME, SERVER_INFO, LIST_FILES
  uploadbad <path>      DEMO ONLY: corrupts one byte to show an integrity error
  help / quit

PROTOCOL (text lines ending in newline, fields separated by '|')
  LOGIN|user  USERS  LIST_FILES  UPLOAD|name|size|sha256  DOWNLOAD|name
  RUN|CMD  LOGOUT
  Replies: OK|..  ERROR|reason  READY  FILE|name|size|sha256
  FILE_OK|name  FILE_ERROR|name   (hash match / mismatch)
After UPLOAD/FILE metadata, exactly <size> raw bytes follow, sent in chunks.

FILE LOCATIONS
  Server files: server_files/   Client downloads: downloads/   Log: server.log

SAFETY
  The server never runs client text in a shell. Only the allow-list in
  ALLOWED_COMMANDS (server.py) works; anything else is rejected.
