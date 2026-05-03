"""
Concurrent port scanner — scans your own machine for open ports.

A "port" is a numbered door on a computer. Web servers usually listen
on port 80 or 443, SSH on 22, etc. A port scan knocks on each door
and notes which ones answer.
"""

import socket
import threading
import time
from queue import Queue

# --- Configuration ---
TARGET = "127.0.0.1"            # localhost = your own machine. Don't change this.
PORTS_TO_SCAN = range(1, 1025)  # the 1024 "well-known" ports
THREAD_COUNT = 1                # scan 100 ports at once (this is what makes it fast)
TIMEOUT = 0.5                   # seconds to wait per port before giving up

# Shared state across threads
port_queue = Queue()
open_ports = []
lock = threading.Lock()

def scan_port(port):
    """Try to open a TCP connection to a port. If it succeeds, the port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    result = s.connect_ex((TARGET, port))   # 0 means "connection succeeded"
    s.close()

    if result == 0:
        try:
            service = socket.getservbyport(port)   # what service usually lives here?
        except OSError:
            service = "unknown"
        with lock:                                  # only one thread prints at a time
            open_ports.append((port, service))
            print(f"  [+] Port {port:5d} OPEN  ({service})")

def worker():
    """Pull ports off the queue and scan them until the queue is empty."""
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(port)
        port_queue.task_done()

# --- Main program ---
for port in PORTS_TO_SCAN:
    port_queue.put(port)

print(f"Scanning {TARGET} ports {PORTS_TO_SCAN.start}-{PORTS_TO_SCAN.stop - 1}...\n")
start = time.time()

threads = []
for _ in range(THREAD_COUNT):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()   # wait for every thread to finish

elapsed = time.time() - start
print(f"\nDone in {elapsed:.2f}s. Found {len(open_ports)} open ports.")
