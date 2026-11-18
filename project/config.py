"""Shared settings for the TCP client/server project.
Change values here only - server.py and client.py both import this file."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Network ---
HOST = "0.0.0.0"            # server listens on all network cards
PORT = 5000                 # server port
DEFAULT_SERVER_HOST = "127.0.0.1"   # client default (use the server's LAN IP for real demo)

# --- Protocol ---
ENCODING = "utf-8"
SEPARATOR = "|"
MAX_LINE = 4096             # max length of one command line (bytes)

# --- Files ---
CHUNK_SIZE = 4096           # bytes per send/recv chunk
HASH_CHUNK_SIZE = 4096      # bytes read per step when hashing
MAX_FILE_SIZE = 200 * 1024 * 1024   # 200 MB upload limit
SERVER_FILES_DIR = os.path.join(BASE_DIR, "server_files")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")

# --- Logging ---
LOG_FILE = os.path.join(BASE_DIR, "server.log")
