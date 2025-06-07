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


