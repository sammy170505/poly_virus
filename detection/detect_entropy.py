"""
Static dector for entropy
Flags files with 
    (a) entropy > 4.5 
    (b) 'exec(base64' pattern.
"""

from utils.entropy import entropy
from pathlib import Path
import re, json, sys

# ----- Configuration -----
ROOT = Path(__file__).resolve().parent.parent
BOX  = ROOT / "sandbox"
THRESHOLD = 4.5
#This will match 'exec(base64' in any case
PATTERN = re.compile(r'exec\s*\(\s*base64', re.IGNORECASE)

def detect_entropy(file_path: Path) -> dict:
    try:
        # Read raw bytes so that it is accurate
        raw = file_path.read_bytes()
        entropy_score = entropy(raw)

        # Convert to text only for pattern scan
        # This might crash if there are binary data or corupt character so use ignore
        text = raw.decode(errors='ignore')

    except Exception as e:
        return {"file": file_path.name, "error": str(e)}

    # Check entropy and pattern
    pattern_hit = bool(PATTERN.search(text))
    suspicious = (entropy_score > THRESHOLD) or pattern_hit

    return {
        "file": file_path.name,
        "entropy": round(entropy_score, 2), # round to 2 decimal places
        "pattern": pattern_hit,
        "suspicious": suspicious
    }

"""Scan all .py files in the sandbox folder."""
def main():
    results = []

    print("\nScanning sandbox/ for suspicious files:\n")
    for file_path in BOX.glob("*.py"):
        result = detect_entropy(file_path)
        results.append(result)

        # Console output
        if "error" in result:
            print(f"[ERROR] {result['file']}: {result['error']}")
        else:
            status = "Suspicious" if result['suspicious'] else "Clean"
            
            # Print in columns
            print(f"{result['file']:20} | Entropy: {result['entropy']:4} | Pattern: {str(result['pattern']):5} | {status}")
            # payload_clone.py      | Entropy: 5.7 | Pattern: True  | Suspicious

    # Save to JSON
    result_file = ROOT / "detection" / "entropy_results.json"
    result_file.parent.mkdir(exist_ok=True)
    with open(result_file, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"\n Scan complete. Results saved to {result_file}")

if __name__ == "__main__":
    main()
    sys.exit(0)
