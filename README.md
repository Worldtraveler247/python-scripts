# python-scripts

A growing collection of small, single-purpose Python scripts I've written while studying DevSecOps and cloud security. Each one solves a real operational problem and is meant to be **read end-to-end in one sitting** — no framework setup, no hidden magic, just stdlib (or near it) Python you can copy onto a fresh machine and run.

| Day | Script | Purpose |
|---|---|---|
| 1 | [`day1/portscan.py`](day1/portscan.py) | Concurrent TCP port scanner against `127.0.0.1`. Knocks on each port and reports which ones answer. |
| 2 | [`day2/integrity_check.py`](day2/integrity_check.py) | SHA-256 file integrity checker. Computes a file's cryptographic fingerprint and optionally compares it against a known-good hash to detect tampering. |

---

## Day 1 — `portscan.py`: concurrent localhost port scanner

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
python3 day1/portscan.py
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

## Day 2 — `integrity_check.py`: SHA-256 file integrity checker

A ~30-line script that reads a file, computes its **SHA-256 hash** (a cryptographic fingerprint of the file's bytes), and — if you give it a previously-recorded hash to compare against — tells you whether the file has been modified. It uses two stdlib modules: `hashlib` (the cryptographic hashing library) and `sys` (to read command-line arguments).

### How it works (the mechanics)

1. **Read the file as raw bytes.** The file is opened in binary mode (`"rb"`). Hashes are defined on bytes, not characters, so we never decode the contents — we just hand the raw bytes to the hasher exactly as they appear on disk.
2. **Feed the bytes into a SHA-256 hasher.** `hashlib.sha256()` returns a "hasher object." You call `.update(data)` to feed it bytes. Internally, the algorithm chews through the input in 512-bit blocks and maintains a running 256-bit state.
3. **Read the fingerprint out.** `.hexdigest()` finalizes the computation and returns a 64-character hex string — the same format you'd get from `shasum -a 256`.
4. **Compare to expected (optional).** If you passed a second command-line argument, the script compares your computed hash to it and prints `OK` or `MISMATCH`.

That's the entire program. There's no I/O cleverness, no concurrency, no error-recovery — the script is meant to be small enough that you can hold the whole thing in your head while reading it.

### What hashing actually means

Think of a hash as a **fingerprint for data**:

- Two identical files → identical fingerprints, every time, on every machine.
- Change **one byte** of the file → the fingerprint becomes completely different. Not "a little different" — totally different. `cca39f85...` becomes something like `7b2e91c7...` with no resemblance to the original. (This is called the **avalanche property**.)
- You **cannot reverse it.** Given the fingerprint, you cannot reconstruct the file. It's a one-way street. That's why hashes are also called **one-way functions**.
- The fingerprint is always the same length (64 hex characters / 256 bits for SHA-256), whether you hashed a 5-byte file or a 5-gigabyte ISO.

The technical name for this is a **cryptographic hash function**. SHA-256 is one specific algorithm; the "256" means the output is 256 bits long. Other family members include SHA-1 (160-bit, considered broken for security purposes since 2017's SHAttered collision), MD5 (128-bit, broken since 2004 — still useful as a checksum, never as a security primitive), and SHA-3 / BLAKE2 / BLAKE3 (modern alternatives).

### Importance for a DevSecOps engineer

Hashes solve one fundamental problem: **"how do I know this file hasn't been changed?"** That question shows up everywhere in security. Five concrete scenarios:

1. **Software supply chain.** You download Docker, kubectl, a Linux ISO, or a Python package on a fresh laptop. How do you know the installer wasn't swapped out by an attacker who compromised the mirror server? You compare the SHA-256 of what you downloaded against the hash that the project publishes on their website. If the hashes match, the file is genuine. If they don't, throw it away. This is why every legitimate software project publishes hashes alongside their downloads — and why supply-chain attacks like SolarWinds and the 2024 XZ Utils backdoor are so dangerous when the published hash itself is part of what got tampered with.

2. **Detecting a server compromise.** An attacker breaks into a Linux box and replaces `/usr/bin/ssh` with a backdoored version that logs every password typed at it. The file looks identical from the outside — same name, same permissions, similar size. But its hash is different. Tools like **AIDE** and **Tripwire** hash every important system file when the server is healthy ("baseline"), store those hashes in a tamper-resistant database, then re-hash daily and alert on any mismatch. That's **File Integrity Monitoring (FIM)**, and PCI-DSS, HIPAA, and SOC 2 all require it for production systems handling regulated data. This script is the nucleus of that workflow.

3. **Git itself runs on hashes.** Every commit, tree, and blob in Git is identified by a SHA-1 hash of its contents. That's why commit IDs look like `235527c...`. Git uses hashes to detect corruption (`git fsck`) and to make history tamper-evident — if someone silently rewrites an old commit, every later commit's hash changes too, and the rewrite is immediately visible to anyone with the original chain. The same idea powers Bitcoin and every blockchain on top of it: a chain of hashes is a chain of evidence.

4. **Password storage.** Servers don't store your actual password. They store a salted hash of it. When you log in, the server hashes what you typed and compares the result to the stored hash. Even if the database leaks, attackers don't get your password directly — they have to **crack the hash**, which means guessing candidate passwords, hashing each one, and looking for a match. (That's exactly what tools like `hashcat` and `john` do, and what a future day in this series will demonstrate against a hash you generate yourself.)

5. **Evidence integrity in incident response.** When a security analyst seizes a hard drive image during an investigation, the very first thing they do is compute its SHA-256. That hash gets recorded in a chain-of-custody document. Months later in court, they re-hash the disk image to prove "this is the same data we collected, untouched." If the hashes don't match, the evidence can be ruled inadmissible. The same pattern applies to log archives, memory dumps, and any artifact whose authenticity might be challenged later.

### The bigger picture

This 30-line script is a toy version of the same primitive that underlies:

- Software downloads (every `.iso`, `.dmg`, `.exe`, `.deb`, and `.whl` on the internet ships with a published hash)
- Git's entire data model
- Bitcoin and every blockchain
- Password authentication on every login form ever
- TLS certificates and code-signing (the lock icon in your browser; the "verified publisher" prompt on Windows)
- Digital signatures and JWT tokens
- File Integrity Monitoring on production servers

Hashing isn't a niche tool — it's one of about five primitive building blocks that all of modern computer security is constructed from. Once you've watched 30 lines of Python compute the same SHA-256 that `shasum -a 256` produces, the lock icon in your browser, `git commit`, Docker image verification, and `apt-get install` all stop feeling magical and start feeling like obvious applications of one idea: **a fingerprint that proves nothing has changed.**

### Quick start

```bash
git clone https://github.com/Worldtraveler247/python-scripts.git
cd python-scripts

# Make a test file
echo "hello devsecops" > test.txt

# Compute its hash (no expected value yet — just see the fingerprint)
python3 day2/integrity_check.py test.txt

# Re-run with the hash you got — should report OK
python3 day2/integrity_check.py test.txt <paste-the-hash-here>

# Tamper with the file, re-run with the OLD hash — should report MISMATCH
echo "attacker was here" >> test.txt
python3 day2/integrity_check.py test.txt <paste-the-OLD-hash-here>
```

No dependencies; uses only the standard library. Tested on macOS and Linux with Python 3.9+. Sanity-check by comparing against `shasum -a 256 <file>` — outputs must match byte-for-byte.

### Sample output

```
File:     test.txt
SHA-256:  cca39f85de05ddb7276165eb636056553b320e7ab8701a1075f9e5d272ebfa23
(no expected hash provided — nothing to compare against)
```

After the file is modified:

```
File:     test.txt
SHA-256:  3f2b91c7e8a4d5b6f0c1e2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3
Expected: cca39f85de05ddb7276165eb636056553b320e7ab8701a1075f9e5d272ebfa23
MISMATCH — file has been modified or is corrupted!
```

### Ethics note

This script is **safe by construction.** It only reads files on your own machine and computes a one-way fingerprint — no network, no writes, no privilege escalation. SHA-256 is one-way: you cannot recover file contents from a hash, so passing a hash around is not equivalent to leaking the file.

The thing to understand is that *the hash itself reveals nothing about the contents*, but it **does** prove a file existed in a specific state at a specific time. That's why hashes show up in legal evidence and audit logs — they're a privacy-preserving way to commit to "this exact data, no other."

### Where to take it next

Natural extensions worth building, each one a separate small script in this series:

- **Multi-file baseline.** Walk a directory tree, hash every file, save results as JSON. On subsequent runs, diff against the baseline and exit non-zero if any hash changed, any file was added, or any file was deleted. Now you've built a minimal AIDE.
- **Streaming hash for large files.** Replace `f.read()` with a chunked loop (`while chunk := f.read(65536)` if you're on Python 3.8+, or a plain `while` loop otherwise). Hash a multi-gigabyte file without loading it all into memory.
- **HMAC instead of plain hash.** Use `hmac.new(key, data, hashlib.sha256)` to compute a *keyed* hash. Plain hashes prove "the file hasn't changed"; HMACs prove "the file hasn't changed AND was produced by someone who knows the secret key." That's how API request signing works (AWS SigV4, GitHub webhooks, Stripe webhooks).
- **Hash cracker.** Generate a SHA-256 hash of a known short password, then write a loop that hashes every line in a wordlist file and stops when it finds a match. You've just built `hashcat` in 15 lines, and you'll viscerally understand why short passwords without salting are catastrophic.
- **Verify a real download.** Pick a project that publishes hashes (e.g., a Linux ISO, a Python release). Download the file, hash it with this script, compare to the published value. You've now done the same supply-chain check that careful operators do by reflex.

Each extension teaches a different facet of how cryptographic hashing shows up in real systems.

---

## License

MIT. Run on systems you own.
