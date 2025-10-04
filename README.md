# HARMFuzz: An Efficient QEMU-Assisted Hybrid ARM Fuzzer

**HARMFuzz** is an ARM-specific hardware fuzzing framework built on top of **AFL++** and **QEMU**.  
It is designed to uncover vulnerabilities in ARM processors by combining emulated environments with hardware-assisted testing.  
Unlike traditional fuzzers that focus on software vulnerabilities, HARMFuzz directly addresses challenges unique to ARM hardware, enabling higher code coverage and the discovery of processor-specific bugs.

---

## Abstract

ARM architectures are central to modern devices, making their security critical.  
Fuzzing has shown promising results in detecting vulnerabilities; however, traditional fuzzing tools focus on software vulnerabilities and are not designed to interact directly with hardware or emulate processor-specific behaviors, leaving a critical gap in detecting flaws unique to hardware implementations.  

The core question of this research is: **how can differential fuzzing identify vulnerabilities in ARM processors, considering their hardware complexity, by integrating emulated environments with hardware testing?**  

HARMFuzz provides an answer by introducing an efficient, ARM-specific, black-box hardware fuzzing tool. It builds on AFL++ and QEMU, but modifies their design to overcome fuzzing limitations, including:  

- **No trimming** and **dynamically controlled mutations** without altering input file size.  
- **Improved hardware awareness**, achieved through QEMU and KVM integration without requiring internal processor knowledge.  
- **Enhanced coverage**, achieving up to *1,000 additional edges* in QEMU-only environments and *100 additional edges* in KVM-enabled scenarios compared to state-of-the-art approaches.  

By systematically addressing these challenges, HARMFuzz advances the state of ARM fuzzing, highlights its potential for improving ARM chip security, and opens pathways for future work in hybrid hardware fuzzing.  

---

## Requirements

### Hardware
- A **high-performance host machine** to run AFL++ and QEMU for generating test cases.
- A **target ARM test device** supporting **KVM** (tested on **Raspberry Pi 4 Model B with Cortex-A72**).

### Software
- [QEMU](https://www.qemu.org/) (with ARM support)  
- [AFL++](https://github.com/AFLplusplus/AFLplusplus)  
- Linux environment (Ubuntu recommended)  

---

## Installation & Setup

1. **Modify AFL++ to support HARMFuzz:
  - Navigate to custom_mutators/aflpp/
  - Replace or patch aflpp.c with the custom code provided in the mutators folder of this project.
2. Deploy to test device (e.g., Raspberry Pi 4):
  - Install QEMU and AFL++ on the ARM device as well.
  - Ensure KVM is enabled (/dev/kvm available).

---

## Usage
1. Generate test cases on the host machine using AFL++ with QEMU instrumentation.
2. Run tests on target device with KVM enabled for hardware-assisted fuzzing.
3. HARMFuzz will automatically manage input mutations, avoiding file-size changes and ensuring coverage growth.
4. 
---

## Results
1. Improved Coverage:
- +1,000 additional edges in QEMU-only setups.
- +100 additional edges in KVM-enabled scenarios.
2. Processor-Aware Fuzzing: Able to discover ARM-specific bugs without requiring full internal processor code access.
3. Practical Validation: Successfully tested on Raspberry Pi 4 Model B (Cortex-A72).

---

```
HARMFuzz/
│
├── mutators/                # Custom AFL++ mutator code
├── scientific_papers/       # Bibliography and related work
└── README.md                # This file
```

---

## Bibliography
Relevant scientific papers, background references, and detailed bibliography can be found in the scientific_papers/ folder.
