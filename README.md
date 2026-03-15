# Fault-Injection-on-AES-128

## Repository Structure
```text
Fault-Injection-on-AES-128/
├── README.md
├── .gitignore
├── Code/
│   ├── Matlab Code/
│   │   ├── lab_task2_123.m
│   │   └── matlab_code.mat
│   └── Python Code/
│       ├── aes128.py
│       └── Lab2_DFA.py
└── Raw_Data/
    ├── attack_data_10k.mat
    ├── constants.mat
    └── dpa_attack_results.mat
```

## Overview

This project explores active hardware attacks by injecting Electromagnetic (EM) faults into an AES-128 encryption engine running on an STM32 microcontroller. Using a precise pulse generator and EM probe, we successfully induced computational errors and applied Differential Fault Analysis (DFA) to mathematically derive the secret key from the faulty ciphertexts.

⚙️ The Attack Vector
We targeted the AddRoundKey operation of Round 8.
•	Hardware Setup: An EM probe was positioned over the microcontroller core.

•	Timing: A hardware trigger (GPIO) was inserted in the firmware to signal the start of Rounds 8-10.

•	Injection: A short, high-intensity EM pulse was injected with nanosecond precision to corrupt the state matrix.


🧮 Differential Fault Analysis (DFA)

The attack relies on the propagation of faults through the AES diffusion layer (MixColumns):
1.	Fault Model: A single byte fault injected in Round 8 spreads to 4 bytes in the final ciphertext.

2.	Data Collection: Collected pairs of (Plaintext, Correct Ciphertext, Faulty Ciphertext).


3.	Key Recovery:
o	Constructed a system of equations linking the differential (Correct ⊕ Faulty) to the Last Round Key (K10).
o	Solved for K10 by filtering candidates that satisfied the Rijndael diffusion constraints.
o	Reversed the Key Schedule to obtain the Master Key.

🛡️ Countermeasures Studied

This project highlights the necessity of hardening techniques:
•	Redundancy: Computing AES twice and comparing results.

•	Infection: Randomizing the output if a fault is detected to prevent DFA.


•	Hardened Cores: Using dual-rail logic.

🛠️ Technologies
•	Equipment: Pulse Generator, EM Probe, XYZ Table, Oscilloscope.

•	Target: STM32 Nucleo (ARM Cortex-M).


•	Software: Python (Analysis scripts), C (Target Firmware).

________________________________________
Author: Uzair Ashfaq

