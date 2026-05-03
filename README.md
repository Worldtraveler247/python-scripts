# python-scripts

A growing collection of small, single-purpose Python scripts I've written while studying DevSecOps and cloud security. Each one solves a real operational problem and is meant to be **read end-to-end in one sitting** — no framework setup, no hidden magic, just stdlib (or near it) Python you can copy onto a fresh machine and run.

| Script | Purpose |
|---|---|
| [`portscan.py`](portscan.py) | Concurrent TCP port scanner against `127.0.0.1`. Knocks on each port and reports which ones answer. |

---

## `portscan.py` — concurrent localhost port scanner

A ~65-line port scanner that uses Python's stdlib (`socket`, `threading`, `queue`) to ask the operating system *"which TCP ports are listening on this machine?"* It's hardcoded to `127.0.0.1` — your own loopback interface — and the comment in the source explicitly says **"Don't change this."** That's deliberate (see [Ethics & legality](#ethics--legality) below).

### How it works (the mechanics)

1. **Build a queue of ports to check.** By default the well-known range, 1–1024.
2. **Spawn N worker threads.** Each worker pulls a port off the queue and tries to open a TCP connection to it.
3. **`socket.connect_ex((host, port))`** is the core trick. Unlike `connect()`, this doesn't raise on failure — it returns `0` on success, a non-zero errno otherwise. That makes scanning a tight loop instead of a try/except dance.
4. **`socket.getservbyport(port)`** asks the OS what service "usually" lives on that port (looks up `/etc/services`). So 22 prints as `ssh`, 80 as `http`, 443 as `https`, etc.
5. **A `threading.Lock`** serializes the prints and the shared `open_ports` list so output doesn't interleave.

This is the simplest variant of a port scan: a **TCP connect scan**. It's the same thing `nmap -sT` does, just without the wire-level wizardry. (`nmap` can also do `-sS`, a SYN-scan, that fires raw packets without completing the handshake — more stealthy, but requires root because raw sockets do.)

### Importance for a DevSecOps engineer

Port scanning is *foundational* for the DevSecOps and cloud security mindset, even though the tool itself is small. Five concrete reasons:

1. **Attack-surface awareness.** Every port that's open is a service that's listening. Every listening service is a piece of code that can be exploited. The first question in any security review of a system is *"what's listening?"* — and you can't answer it from a config file alone, because reality drifts: a developer enabled debug-mode on port 8080 and forgot, an old service is still bound, a container exposes a port the deploy spec didn't mention. A port scan is **ground truth**.

2. **Baseline and detect drift.** A senior-engineer pattern: scan the box once, save the output as the *expected* baseline, then scan periodically and diff. New port appearing? That's a deploy you didn't know about, a backdoor, or a misconfigured agent. The cheapest IDS in the world is `nmap` + `diff`. This script is the nucleus of that workflow.

3. **CI/CD pipeline gate.** When you build a container or a VM image, scan it as part of CI. Fail the pipeline if anything is open beyond the explicit allowlist. *("This image must only expose 8080. Trivy scan: ✓. Port scan: ✓ (only 8080 listening). Approved for deploy.")* That's a real DevSecOps control, and it's literally this script in a loop.

4. **Cloud-context translation.** The same idea scales: AWS Security Group is a port allowlist enforced at the hypervisor; Kubernetes `NetworkPolicy` is a port allowlist enforced at the CNI; macOS `pf` and Linux `iptables`/`nftables` are port allowlists at the kernel. Once you've seen `connect_ex` return 0 on a port you didn't expect, you internalize *why* every layer of the stack has to enforce its own allowlist — defense in depth isn't a slogan, it's the only thing that catches a misconfiguration in any single layer.

5. **Capital One pattern recognition.** The 2019 Capital One breach hinged on a service listening on a port that was reachable from outside the VPC. A junior engineer who has never run a port scan in anger doesn't intuitively grasp how that mistake happens. A junior engineer who has watched their own laptop cough up an unexpected open port at 03:00 understands it in their bones. That's the difference between *"I read about this CVE"* and *"I ship this control."*

### Quick start

```bash
git clone https://github.com/Worldtraveler247/python-scripts.git
cd python-scripts
python3 portscan.py
```

No dependencies; uses only the standard library. Tested on macOS and Linux with Python 3.9+.

### Sample output

```
Scanning 127.0.0.1 ports 1-1024...

  [+] Port    22 OPEN  (ssh)
  [+] Port    80 OPEN  (http)
  [+] Port   631 OPEN  (ipp)

Done in 1.84s. Found 3 open ports.
```

### Tuning knobs (in source)

| Constant | Default | What it controls |
|---|---|---|
| `TARGET` | `127.0.0.1` | The host to scan. **Leave at loopback.** Scanning anything else is your own legal exposure (see below). |
| `PORTS_TO_SCAN` | `range(1, 1025)` | Port range. Bump to `range(1, 65536)` for a full sweep — slower. |
| `THREAD_COUNT` | `1` | Workers in parallel. Bumping this to ~100 makes the full-range scan ~100× faster. |
| `TIMEOUT` | `0.5` | Seconds to wait per port before giving up. Lower = faster scan, more false negatives on slow services. |

> **Heads-up:** the source has `THREAD_COUNT = 1` with a comment that says "scan 100 ports at once." The comment is a relic from when the default was 100; the code is currently single-threaded. Set it to `100` for the speed-up. (Worth fixing in the source — left as-is here so the script in the repo matches what got committed.)

### Ethics & legality

**Only scan systems you own or have explicit written authorization to scan.**

In the United States, unauthorized port scanning of systems you don't control can fall under the **Computer Fraud and Abuse Act (CFAA)**. In the UK it's the **Computer Misuse Act 1990**. Most other countries have analogous laws. "I was just scanning, I didn't break in" is not a defense — *probing* is itself the conduct prohibited.

The hardcoded `TARGET = "127.0.0.1"` keeps you on your own loopback interface, which is your own machine talking to itself — no network packets leave the box. That is the safest possible default.

If you want to scan something else:
- A VM or container you own → fine.
- An EC2 instance in your own AWS account → fine, but be aware AWS used to require advance notice for large scans (no longer required for most cases since 2019, but check current policy).
- A bug-bounty target with explicit scope → fine, within their stated scope.
- Anything else → don't.

This is the same boundary that came up in the previous DevSecOps Job Hub work: cybersecurity people are held to a higher standard if anything is questioned. "I knew what I was doing" cuts both ways.

### Where to take it next

Natural extensions worth building, each one a separate small script in this repo:

- **Banner grabbing.** After `connect_ex` returns 0, send a small probe (`HEAD / HTTP/1.0\r\n\r\n` for 80/443, an empty line for SSH/SMTP) and read the response — identify the actual service version, not just the well-known guess.
- **Baseline diff.** Save the open-port list to JSON; on subsequent runs, diff against the baseline and exit non-zero if anything's new. CI-friendly.
- **CIDR sweep.** Take a small `/24` and scan one chosen port across every host. Authorization required.
- **UDP support.** UDP scans are harder (there's no handshake), but `socket.SOCK_DGRAM` plus a timeout-and-listen pattern is enough for the common services.
- **Replace threads with `asyncio`.** Same model, lower overhead at high concurrency. Good chance to learn `asyncio.open_connection`.

Each of those is the kind of thing a DevSecOps engineer ships to a team's internal toolbox.

---

## License

MIT. Run on systems you own.
