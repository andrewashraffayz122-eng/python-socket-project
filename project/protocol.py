"""Message format + helpers shared by server and client.

Every request/response is ONE text line ending with '\n':
    COMMAND|ARG1|ARG2
File bytes are sent right after the metadata line (exactly <size> bytes),
because TCP is a byte stream with no message boundaries.

Requests : LOGIN|user  USERS  LIST_FILES  UPLOAD|name|size|sha256
           DOWNLOAD|name  RUN|CMD  LOGOUT
Replies  : OK|...   ERROR|reason   READY   FILE|name|size|sha256
Integrity: FILE_OK|name|hash   FILE_ERROR|name|reason
"""
import hashlib
import os

from config import CHUNK_SIZE, ENCODING, HASH_CHUNK_SIZE, MAX_LINE, SEPARATOR


class ProtocolError(Exception):
    """Raised when a received message is malformed."""


def sha256_file(path):
    """SHA-256 of a file, read in chunks (works for large files)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name):
    """Return a bare file name, or None if unsafe (blocks ../../x, empty, '|')."""
    base = os.path.basename(name.replace("\\", "/"))
    if not base or base in (".", "..") or SEPARATOR in base or "\n" in base:
        return None
    return base


class Connection:
    """Wraps a socket: line-based messages + exact-size binary transfer."""

    def __init__(self, sock):
        self.sock = sock
        self.rfile = sock.makefile("rb")      # buffered reader (handles partial recv)

    # ---------- text messages ----------
    def send(self, *parts):
        line = SEPARATOR.join(str(p) for p in parts) + "\n"
        self.sock.sendall(line.encode(ENCODING))

    def recv(self):
        """Return the message as a list of parts, or None if peer closed."""
        raw = self.rfile.readline(MAX_LINE)
        if not raw:
            return None
        if not raw.endswith(b"\n"):
            raise ProtocolError("Message too long or incomplete")
        text = raw.decode(ENCODING, errors="replace").rstrip("\r\n")
        return text.split(SEPARATOR)

    # ---------- binary (file) transfer ----------
    def send_file(self, path, corrupt_first_byte=False):
        """Send a file in CHUNK_SIZE pieces. corrupt_first_byte is for the
        integrity-error demo only (flips one bit AFTER the hash was computed)."""
        first = True
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if first and corrupt_first_byte:
                    chunk = bytes([chunk[0] ^ 0x01]) + chunk[1:]
                first = False
                self.sock.sendall(chunk)

    def recv_file(self, path, size):
        """Receive EXACTLY `size` bytes in chunks and save them to `path`."""
        remaining = size
        with open(path, "wb") as f:
            while remaining > 0:
                data = self.rfile.read(min(CHUNK_SIZE, remaining))
                if not data:
                    raise ConnectionError("Connection lost during file transfer")
                f.write(data)
                remaining -= len(data)

    def close(self):
        try:
            self.rfile.close()
        finally:
            self.sock.close()
