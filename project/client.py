"""Command-line TCP client.  Usage:  python client.py [server_ip] [port]"""
import os
import socket
import sys

import config
from protocol import Connection, safe_filename, sha256_file

HELP = """
Commands:
  users                 show online users
  list                  show files on the server
  upload <path>         upload a file (SHA-256 verified)
  download <filename>   download a file (SHA-256 verified)
  run <COMMAND>         run approved server command (TIME, HOSTNAME, SERVER_INFO, LIST_FILES)
  uploadbad <path>      DEMO ONLY: upload with a corrupted byte to show an integrity error
  help                  show this help
  quit                  logout and exit
"""


def upload(conn, path, corrupt=False):
    if not os.path.isfile(path):
        print("Local file not found:", path)
        return
    name = safe_filename(path)
    size = os.path.getsize(path)
    digest = sha256_file(path)                       # hash BEFORE sending
    print(f"Local SHA-256 : {digest}")
    conn.send("UPLOAD", name, size, digest)
    reply = conn.recv()
    if reply is None or reply[0] != "READY":
        print("Server refused:", reply[1] if reply and len(reply) > 1 else reply)
        return
    conn.send_file(path, corrupt_first_byte=corrupt)
    result = conn.recv()
    if result and result[0] == "FILE_OK":
        print(f"Server SHA-256: {result[2]}")
        print(f"[OK] Hashes match - upload of '{name}' completed.")
    else:
        print("[INTEGRITY ERROR] Upload NOT successful:", result[2] if result and len(result) > 2 else result)


def download(conn, name):
    conn.send("DOWNLOAD", name)
    reply = conn.recv()
    if reply is None:
        raise ConnectionError("Server closed the connection")
    if reply[0] != "FILE":
        print("Error:", reply[1] if len(reply) > 1 else reply)
        return
    _, fname, size, expected = reply
    os.makedirs(config.DOWNLOADS_DIR, exist_ok=True)
    final_path = os.path.join(config.DOWNLOADS_DIR, safe_filename(fname))
    temp_path = final_path + ".part"
    conn.recv_file(temp_path, int(size))             # exactly `size` bytes, in chunks
    actual = sha256_file(temp_path)                  # hash AFTER saving
    print(f"Expected SHA-256  : {expected}")
    print(f"Calculated SHA-256: {actual}")
    if actual == expected:
        os.replace(temp_path, final_path)
        conn.send("FILE_OK", fname)
        print(f"[OK] Hashes match - '{fname}' saved to downloads/")
    else:
        os.remove(temp_path)
        conn.send("FILE_ERROR", fname)
        print("[INTEGRITY ERROR] Hash mismatch - file discarded, download NOT successful.")


def show(reply, what):
    if reply is None:
        raise ConnectionError("Server closed the connection")
    if reply[0] == "OK":
        text = reply[1] if len(reply) > 1 else ""
        items = [i for i in text.split(",") if i] if what in ("users", "list") else [text]
        print(f"--- {what} ---")
        for i in items or ["(empty)"]:
            print(" ", i.replace(":", "  (") + " bytes)" if what == "list" and ":" in i else i)
    else:
        print("Error:", reply[1] if len(reply) > 1 else reply)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else input(f"Server IP [{config.DEFAULT_SERVER_HOST}]: ").strip() or config.DEFAULT_SERVER_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else config.PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"Cannot connect to {host}:{port} - {e}")
        return
    conn = Connection(sock)
    print(f"Connected to {host}:{port}")

    try:
        while True:                                  # login (retry if name is taken)
            name = input("Username: ").strip()
            conn.send("LOGIN", name)
            reply = conn.recv()
            if reply is None:
                print("Server closed the connection")
                return
            print(reply[1] if len(reply) > 1 else reply[0])
            if reply[0] == "OK":
                break
        print(HELP)

        while True:
            line = input(f"{name}> ").strip()
            if not line:
                continue
            cmd, _, arg = line.partition(" ")
            cmd, arg = cmd.lower(), arg.strip()
            if cmd == "users":
                conn.send("USERS"); show(conn.recv(), "users")
            elif cmd == "list":
                conn.send("LIST_FILES"); show(conn.recv(), "list")
            elif cmd in ("upload", "uploadbad") and arg:
                upload(conn, arg.strip('"'), corrupt=(cmd == "uploadbad"))
            elif cmd == "download" and arg:
                download(conn, arg)
            elif cmd == "run" and arg:
                conn.send("RUN", arg); show(conn.recv(), "result")
            elif cmd == "help":
                print(HELP)
            elif cmd in ("quit", "exit", "logout"):
                conn.send("LOGOUT"); print(conn.recv()); break
            else:
                print("Invalid command. Type 'help'.")
    except (ConnectionError, OSError) as e:
        print("Connection error:", e)
    except (KeyboardInterrupt, EOFError):
        print("\nBye")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
