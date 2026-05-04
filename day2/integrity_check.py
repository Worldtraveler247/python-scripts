# A simple file integrity checker.
# Computes a file's SHA-256 hash so you can detect tampering.

import hashlib  # Python's built-in cryptographic hashing library
import sys      # lets us read command-line arguments


def hash_file(filename):
    # Open the file in binary mode ("rb"). Hashes work on raw bytes,
    # not text — we never decode the contents.
    f = open(filename, "rb")
    data = f.read()
    f.close()

    # Create a SHA-256 "hasher", feed it the bytes,
    # and return the hash as a 64-character hex string.
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def check_integrity(filename, expected_hash):
    actual_hash = hash_file(filename)
    print(f"File:     {filename}")
    print(f"SHA-256:  {actual_hash}")

    if expected_hash == "":
        print("(no expected hash provided — nothing to compare against)")
        return

    print(f"Expected: {expected_hash}")
    if actual_hash == expected_hash:
        print("OK — file matches expected hash.")
    else:
        print("MISMATCH — file has been modified or is corrupted!")


# sys.argv is a list of command-line pieces.
# Running:  python3 integrity_check.py myfile.txt abc123
# gives:    sys.argv[0] = "integrity_check.py"
#           sys.argv[1] = "myfile.txt"
#           sys.argv[2] = "abc123"
if len(sys.argv) < 2:
    print("Usage: python3 integrity_check.py <filename> [expected_hash]")
    sys.exit(1)  # exit with a non-zero code = "something went wrong"

filename = sys.argv[1]
expected = ""
if len(sys.argv) >= 3:
    expected = sys.argv[2]

check_integrity(filename, expected)
