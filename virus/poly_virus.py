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

# ---------- Encode payload ----------
encoded = base64.b64encode(PAYLOAD.encode()).decode()