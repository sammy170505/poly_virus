# Polymorphic XOR Virus Lab

This project demonstrates a **polymorphic, self-mutating Python "virus"** with two detection strategies: a simple static detector and a hybrid multi-layered static detector.

## Features

- **Polymorphic Engine**  
  Generates new "virus" clones on each run via XOR encryption, junk code, and randomization.

- **Keylogging Payload**  
  The payload logs keystrokes for 15 seconds, saving to a sandboxed file.

- **Two Automated Detectors**
  - **Static Detector:** Flags files by entropy and suspicious patterns.
  - **Hybrid Detector:** Uses entropy, regex, and YARA rules for in depth analysis.

## Project Structure

```
poly_virus/
│
├── payload.py  # Keylogger payload
├── virus/
│ └── poly_virus.py  # Polymorphic engine
├── sandbox/ # Generated/ran clones
├── detection/
│ ├── detect_entropy.py  # Simple static detector (entropy+regex)
│ ├── hybrid_detector.py  # Hybrid detector (YARA + entropy + regex)
│ ├── entropy_results.json  # Static detector output
│ └── hybrid_results.json  # Hybrid detector output
├── utils/
│ └── entropy.py  # Shannon entropy helper
├── xor_key.txt  # XOR secret key (gitignored)
├── .gitignore
├── requirements.txt
└── README.md
```

##  How It Works

### **1. Payload**
- Minimal keylogger: logs keystrokes for 30s, writes to `sandbox/keylog.txt` and logs infections.

### **2. Polymorphic Engine**
- Reads and XOR-encrypts `payload.py`
- Generates a new Python clone with:
  - Random comments, variable names
  - Embedded encrypted payload
  - Code to decode and execute payload at runtime
- Logs each mutation

### **3. Detection Suite**

#### **A. Static Detector (`detect_entropy.py`)**
- **Entropy:** Flags files above a randomness threshold (packed/encrypted)
- **Regex:** Flags suspicious strings like `exec(base64...`

#### **B. Hybrid Detector (`hybrid_detector.py`)**
- **All the above, plus:**
- **YARA Rules:** Flags files with markers (e.g. use of `tempfile`, dynamic imports, XOR helpers)
- **Consolidated JSON report**
> **Note:** YARA is a signature-based static analysis tool, not a hybrid or anomaly-based method.  
> The “hybrid” detector in this project refers to the combination of YARA signatures, entropy statistics, and regex heuristics in a unified tool.
