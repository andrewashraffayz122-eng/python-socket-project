"""TCP server: accepts many clients (one thread each), handles login,
file upload/download with SHA-256 verification, allow-listed commands, logging."""
import logging
import os
import platform
import socket
import threading
from datetime import datetime

import config
from protocol import Connection, ProtocolError, safe_filename, sha256_file

# ---------------- logging (file + console) ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
              logging.StreamHandler()],
)
log = logging.getLogger("server")

# ---------------- shared state (protected by a lock) ----------------
online_users = {}                 # username -> (ip, port)
users_lock = threading.Lock()


# ---------------- helpers ----------------
def list_server_files():
    """List 'name:size' for each real file (temporary .part files are hidden)."""
    items = []
    for name in sorted(os.listdir(config.SERVER_FILES_DIR)):
        path = os.path.join(config.SERVER_FILES_DIR, name)
        if os.path.isfile(path) and not name.endswith(".part"):
            items.append(f"{name}:{os.path.getsize(path)}")
    return items


# Allow-list: ONLY these commands can be run. Client text is never given to a shell.
ALLOWED_COMMANDS = {
    "TIME": lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "HOSTNAME": socket.gethostname,
    "SERVER_INFO": lambda: f"{platform.system()} {platform.release()} | Python {platform.python_version()}",
    "LIST_FILES": lambda: ", ".join(list_server_files()) or "(no files)",
}


# ---------------- request handlers ----------------
def do_login(conn, parts, addr):
    if len(parts) != 2 or not parts[1].strip():
        conn.send("ERROR", "Usage: LOGIN|username")
        return None
    name = parts[1].strip()
    if not name.replace("_", "").replace("-", "").isalnum() or len(name) > 20:
        conn.send("ERROR", "Username must be letters/digits/_/- (max 20)")
        return None
    with users_lock:
        if name in online_users:
            log.warning("Login rejected (duplicate username '%s') from %s", name, addr)
            conn.send("ERROR", "Username already taken")
            return None
        online_users[name] = addr
    log.info("Login: '%s' from %s", name, addr)
    conn.send("OK", f"Welcome {name}")
    return name


def do_upload(conn, parts, user):
    if len(parts) != 4:
        conn.send("ERROR", "Usage: UPLOAD|filename|size|sha256")
        return
    name = safe_filename(parts[1])
    expected = parts[3].strip().lower()
    if name is None:
        conn.send("ERROR", "Invalid filename")
        return
    try:
        size = int(parts[2])
    except ValueError:
        conn.send("ERROR", "Size must be a number")
        return
    if size < 0 or size > config.MAX_FILE_SIZE or len(expected) != 64:
        conn.send("ERROR", "Invalid size or SHA-256 value")
        return

    final_path = os.path.join(config.SERVER_FILES_DIR, name)
    temp_path = os.path.join(config.SERVER_FILES_DIR, f".{user}_{name}.part")
    log.info("Upload started: '%s' (%d bytes) by %s | expected SHA-256 %s", name, size, user, expected)
    conn.send("READY")                       # client may now send the bytes
    conn.recv_file(temp_path, size)          # exactly `size` bytes, in chunks
    actual = sha256_file(temp_path)          # hash AFTER saving
    if actual == expected:
        os.replace(temp_path, final_path)
        log.info("Upload OK: '%s' | SHA-256 match %s", name, actual)
        conn.send("FILE_OK", name, actual)
    else:
        os.remove(temp_path)                 # never keep a corrupted file
        log.error("Upload INTEGRITY ERROR: '%s' | expected %s | got %s", name, expected, actual)
        conn.send("FILE_ERROR", name, f"Integrity error: expected {expected} but got {actual}")


def do_download(conn, parts, user):
    if len(parts) != 2:
        conn.send("ERROR", "Usage: DOWNLOAD|filename")
        return
    name = safe_filename(parts[1])
    path = os.path.join(config.SERVER_FILES_DIR, name) if name else None
    if not path or name.endswith(".part") or not os.path.isfile(path):
        log.warning("Download failed (file not found): '%s' requested by %s", parts[1], user)
        conn.send("ERROR", "File not found")
        return
    size = os.path.getsize(path)
    digest = sha256_file(path)               # hash BEFORE sending
    log.info("Download started: '%s' (%d bytes) by %s | SHA-256 %s", name, size, user, digest)
    conn.send("FILE", name, size, digest)    # metadata first, then raw bytes
    conn.send_file(path)
    reply = conn.recv()                      # client reports hash comparison result
    if reply and reply[0] == "FILE_OK":
        log.info("Download OK: '%s' verified by client %s", name, user)
    else:
        log.error("Download INTEGRITY ERROR: '%s' reported by client %s: %s", name, user, reply)


def do_run(conn, parts, user):
    if len(parts) != 2:
        conn.send("ERROR", "Usage: RUN|COMMAND")
        return
    cmd = parts[1].strip().upper()
    func = ALLOWED_COMMANDS.get(cmd)
    if func is None:
        log.warning("Rejected command '%s' from %s", parts[1], user)
        conn.send("ERROR", f"Command not allowed. Allowed: {', '.join(ALLOWED_COMMANDS)}")
        return
    output = str(func()).replace("\n", " ")
    log.info("RUN %s by %s -> %s", cmd, user, output)
    conn.send("OK", output)                  # sent only to the requesting client


# ---------------- one thread per client ----------------
def handle_client(sock, addr):
    conn = Connection(sock)
    user = None
    log.info("Connected: %s", addr)
    try:
        while True:
            parts = conn.recv()
            if parts is None:                # client closed the socket
                break
            cmd = parts[0].upper()

            if cmd == "LOGIN":
                if user:
                    conn.send("ERROR", "Already logged in")
                else:
                    user = do_login(conn, parts, addr)
            elif cmd == "LOGOUT":
                conn.send("OK", "Goodbye")
                break
            elif user is None:
                conn.send("ERROR", "Please LOGIN first")
            elif cmd == "USERS":
                with users_lock:
                    names = sorted(online_users)
                conn.send("OK", ",".join(names))
            elif cmd == "LIST_FILES":
                conn.send("OK", ",".join(list_server_files()))
            elif cmd == "UPLOAD":
                do_upload(conn, parts, user)
            elif cmd == "DOWNLOAD":
                do_download(conn, parts, user)
            elif cmd == "RUN":
                do_run(conn, parts, user)
            else:
                log.warning("Invalid request from %s: %s", user or addr, parts)
                conn.send("ERROR", "Unknown command")
    except (ConnectionError, OSError) as e:
        log.error("Connection problem with %s: %s", user or addr, e)
    except ProtocolError as e:
        log.error("Protocol error from %s: %s", user or addr, e)
    except Exception as e:                   # never crash the whole server
        log.exception("Unexpected error with %s: %s", user or addr, e)
    finally:
        if user:
            with users_lock:
                online_users.pop(user, None)
        conn.close()
        log.info("Disconnected: %s (user=%s)", addr, user)


def get_local_ip():
    """Best-effort LAN IP (no data is actually sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def main():
    os.makedirs(config.SERVER_FILES_DIR, exist_ok=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # TCP
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.HOST, config.PORT))
    server.listen()
    log.info("Server started on %s:%d", get_local_ip(), config.PORT)
    print(f"\n=== SERVER RUNNING ===\nIP: {get_local_ip()}   Port: {config.PORT}\nPress Ctrl+C to stop.\n")
    try:
        while True:
            sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        log.info("Server stopped by user")
    finally:
        server.close()


if __name__ == "__main__":
    main()
