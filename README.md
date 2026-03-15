# Fault Injection on AES-128

<!-- Optional banner: replace with your own image path, e.g. assets/banner.png -->
![Project Banner](https://placehold.co/1200x320?text=Fault+Injection+on+AES-128)

Practical **Differential Fault Analysis (DFA)** on an AES-128 implementation, with supporting Python and MATLAB analysis scripts. The workflow demonstrates how injected computation faults can be exploited to recover round-key candidates and reconstruct the AES master key.

> **Key Outcome:** The DFA pipeline filters round-10 key-byte candidates from faulty ciphertext pairs and validates surviving candidates by re-encryption consistency.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Attack Scenario](#attack-scenario)
3. [DFA Methodology](#dfa-methodology)
4. [Repository Structure](#repository-structure)
5. [Python Task — DFA Key Recovery](#python-task--dfa-key-recovery)
6. [MATLAB Task — Correlation Model Study](#matlab-task--correlation-model-study)
7. [Project Highlights](#project-highlights)
8. [Results Summary](#results-summary)
9. [Tech Stack](#tech-stack)
10. [Setup & Usage](#setup--usage)

---

## Project Overview

This project focuses on **active side-channel cryptanalysis** using electromagnetic fault injection against AES-128 on embedded hardware (STM32 class target). Instead of attacking AES mathematically, the attack introduces controlled faults during encryption and uses the resulting output differences to infer secret key material.

Two analysis tracks are included:

- **Python DFA track:** recovers round-10 key candidates and reconstructs the AES-128 master key.
- **MATLAB analysis track:** compares multiple leakage/power models over captured trace datasets.

---

## Attack Scenario

The practical fault setup follows this pattern:

- A hardware trigger (GPIO) marks the relevant encryption rounds.
- An EM pulse is injected with precise timing to corrupt internal AES state.
- Correct and faulty ciphertext pairs are collected for the same plaintext.
- Differential relations from fault propagation are used to constrain the last-round key.

Typical lab instrumentation includes:

- Pulse generator
- EM probe + positioning stage (XYZ table)
- Oscilloscope
- STM32 Nucleo target board

---

## DFA Methodology

### High-Level Flow

1. **Collect Pairs**
    - Gather tuples of `(Plaintext, Correct Ciphertext, Faulty Ciphertext)`.

2. **Build Differential Constraints**
    - Use AES inverse operations around the last round (`InvShiftRows`, `InvSubBytes`) and MixColumns diffusion relations.

3. **Recover K10 Candidates**
    - For each key byte position, test all 256 hypotheses and keep only values consistent with observed fault equations.

4. **Validate Candidate Combinations**
    - Form Cartesian products of surviving per-byte candidates.
    - Reconstruct a master key through inverse key expansion.
    - Verify by checking whether encryption reproduces a known correct ciphertext.

---

## Repository Structure

```text
.
├── README.md
├── Code/
│   ├── Matlab Code/
│   │   └── lab_task2_123.m
│   └── python/
│       ├── aes128.py
│       └── Lab2_DFA.py
└── Raw_Data/
     ├── attack_data_10k.mat
     ├── constants.mat
     ├── dpa_attack_results.mat
     └── matlab_code.mat
```

---

## Python Task — DFA Key Recovery

### `Code/python/Lab2_DFA.py`

Main DFA workflow:

- Uses sample correct/faulty ciphertext triples.
- Computes per-byte candidate lists for the round-10 key.
- Validates candidate tuples against a known plaintext/ciphertext pair.
- Recovers the AES-128 master key with inverse key expansion.

### `Code/python/aes128.py`

AES reference primitives used by DFA:

- AES S-box / inverse S-box
- `SubBytes`, `ShiftRows`, `MixColumns` and inverse transforms
- Key expansion and inverse key expansion
- Forward and inverse AES cipher routines

---

## MATLAB Task — Correlation Model Study

### `Code/Matlab Code/lab_task2_123.m`

This script performs a correlation-based analysis over trace data and compares:

- **Hamming Weight** model
- **Single-bit models** (bit 0 through bit 7)

For each model and attacked byte, it reports:

- Final key guess from peak correlation
- Estimated minimum trace count where that final key guess appears

Required data files are loaded from `Raw_Data/` (`attack_data_10k.mat`, `constants.mat`, etc.).

---

## Project Highlights

| Area | Highlight |
|---|---|
| Attack class | Active fault attack (EM fault injection + DFA) |
| Cryptographic target | AES-128 on embedded hardware (STM32 class platform) |
| Python deliverable | End-to-end DFA candidate filtering + master-key reconstruction |
| MATLAB deliverable | Multi-model correlation study (HW + bit-wise models) |
| Verification strategy | Candidate validation by known plaintext/ciphertext consistency |

---

## Results Summary

| Metric | Outcome |
|---|---|
| K10 key-space reduction | Byte-wise candidate filtering from 256 hypotheses per byte to small valid sets |
| Master-key recovery path | Reconstructed via inverse key expansion from surviving K10 tuples |
| End-state validation | Confirmed by reproducing known correct ciphertext from plaintext |
| Trace-analysis output | Per-model key guesses and minimum-trace estimates per attacked byte |

This gives a full practical chain from **fault injection effects** to **cryptographic key recovery evidence**, with both algorithmic (Python) and statistical (MATLAB) analysis tracks.

---

## Tech Stack

| Layer | Tools |
|---|---|
| Hardware | STM32 Nucleo, EM probe, pulse generator, oscilloscope |
| Python Analysis | Python 3, NumPy |
| MATLAB Analysis | MATLAB with `.mat` trace datasets |

---

## Setup & Usage

### Python (DFA)

```bash
cd Code/python
python Lab2_DFA.py
```

### MATLAB (Correlation Study)

1. Open MATLAB.
2. Change directory to `Code/Matlab Code/`.
3. Ensure required files from `Raw_Data/` are available on the MATLAB path.
4. Run:

```matlab
lab_task2_123
```

---

**Author:** Uzair Ashfaq

