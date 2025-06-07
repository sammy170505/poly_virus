"""
Hybrid static detector
 • Shannon-entropy test
 • Regex for exec(base64
 • Two YARA rules:
      - XOR_Encoded_Payload  (tempfile + exec_module pattern)
      - XOR_Function_Def     (def xor(…) helper functions)
Writes results to detection/hybrid_results.json
"""
import re, json, sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils.entropy import entropy
import yara

# ----- Configuration -----
ROOT = Path(__file__).resolve().parent.parent
BOX  = ROOT / "sandbox"
THRESHOLD = 4.5
#This will match 'exec(base64' in any case
PATTERN = re.compile(r'exec\s*\(\s*base64', re.IGNORECASE)

# ----- YARA rules -----

yara_rules = yara.compile(source=r"""
rule XOR_Encoded_Payload
{
    strings:
        $tempfile    = "tempfile.NamedTemporaryFile" ascii
        $exec_module = "spec.loader.exec_module" ascii
    condition:
        1 of them
}

      rule XOR_Function_Def
{
    strings:
        $xor_func = /def\s+xor(_data)?\s*\(/ nocase wide ascii
    condition:
        $xor_func
}
                          
""")

# ----- Detection function -----
def detect_hybrid(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        text = raw.decode(errors='ignore')
        score = entropy(raw)
        yara_matches = yara_rules.match(data=raw)
        pattern_hit = bool(PATTERN.search(text))
        suspicious = (score > THRESHOLD) or pattern_hit or bool(yara_matches)

        return {
            "file": path.name,
            "entropy": round(score, 2),
            "pattern_hit": pattern_hit,
            "yara_matches": [rule.rule for rule in yara_matches],
            "suspicious": suspicious
        }
    except Exception as e:
        return {
            "file": path.name,
            "error": str(e)
        }
