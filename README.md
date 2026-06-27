# nRF9160 Modem Firmware Rehosting and Fuzzing

This repository contains the code for the partial rehosting harness and fuzzing setup used in the bachelor thesis *"Attack Surface Analysis of nRF9160 Modem Firmware through Reverse Engineering and Fuzzing"* by Kevin Yuan (VU Amsterdam, 2026).

The project analyzes the AT command parsing pipeline of the nRF9160 LTE modem firmware through partial rehosting using the Unicorn Engine and coverage-guided fuzzing using AFL++.

## Repository Structure

| File | Description |
|------|-------------|
| `emulator.py` | Partial rehosting harness — emulates the `process_message` function with hooks for memory allocation, SVC calls, and tracing functions. Can replay AFL++ queue/crash files. |
| `fuzzer.py` | Fuzzing harness — integrates the rehosting harness with AFL++ via unicornafl. Constructs the AT message structure and passes fuzzer-generated input to the parsing pipeline. |
| `coverage.py` | Coverage measurement script — replays all AFL++ queue files through the emulator with basic block tracing enabled and outputs coverage data as JSON. |
| `translate_blocks.py` | Ghidra Jython script — maps Unicorn translation block addresses to Ghidra basic blocks. Run inside Ghidra's Script Manager (set script type to Jython). |
| `plot.py` | Generates median coverage plot with 95% confidence interval using seaborn. |
| `5_plot.py` | Generates individual coverage lines plot for all five runs. |
| `collect_basic_blocks.sh` | Helper script that runs `coverage.py` against each of the five output folders. |
| `start_fuzzers_bl.sh` | Starts five independent baseline fuzzers (no dictionary), each pinned to an even-numbered core for 24 hours. |
| `start_fuzzers_dict.sh` | Starts five independent dictionary-assisted fuzzers with `at_strings.txt`, each pinned to an even-numbered core for 24 hours. |
| `at_strings.txt` | AFL++ dictionary containing AT command names and common parameter tokens. |
| `modem_firmware.bin` | nRF9160 modem firmware binary dump (loaded at base address 0x50000). |
| `translate_blocks.py` | Ghidra Jython script for mapping coverage blocks. |
| `ghidra functions.md` | Documentation of renamed functions discovered during reverse engineering. |

## Requirements

- Linux (tested on Ubuntu 24.04)
- Python 3.8+
- [Unicorn Engine](https://www.unicorn-engine.org/) 2.1.4+ (`pip install unicorn`)
- [unicornafl](https://github.com/AFLplusplus/unicornafl) 3.0.0+ (built from source, requires Rust toolchain and maturin)
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) 4.41a+ (built from source)
- Python packages: `matplotlib`, `seaborn`, `pandas`, `numpy`
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.0.4+ (for `translate_blocks.py` and reverse engineering)

## Installation

```bash
git clone https://github.com/ShiroWasTaken727/nrf9160_emulator.git
cd nrf9160_emulator
pip install unicorn matplotlib seaborn pandas numpy
```

Build unicornafl and AFL++ from source following their respective documentation:
- [unicornafl installation](https://github.com/AFLplusplus/unicornafl/blob/main/docs/python-usage.md)
- [AFL++ installation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md)

## Usage

### Running the Emulator

```bash
python3 emulator.py
```

This runs the AT command parsing pipeline with a hardcoded test input (`AT+CGAUTH=1,1,"username","password"`). Expected output ends with:

```
>>> AT response string: b'AT+CGAUTH=1,1,"username","password"\x00'
```

To replay a specific AFL++ queue or crash file:

```bash
python3 emulator.py path/to/queue/file
```

### Running the Fuzzer

start a single fuzzer:

```bash
afl-fuzz -U -i input -o output -- python3 fuzzer.py @@
```

the fuzzer will automatically generate an input and output folder.

### Running the Evaluation

**Baseline (no dictionary):**
```bash
./start_fuzzers_bl.sh
```

**Dictionary-assisted:**
```bash
./start_fuzzers_dict.sh
```

Both scripts run five independent fuzzers for 24 hours, each pinned to an even-numbered core (0, 2, 4, 6, 8).
the first script runs the baseline fuzzing experiment while the second script runs the dictionary-assisted fuzzing experiment.

## Collecting Coverage

After fuzzing completes run:

```bash
./collect_basic_blocks.sh
```

This runs `coverage.py` on each output directory. Then run `translate_blocks.py` inside Ghidra individually to map to basic blocks, and generate plots using:

```bash
python3 plot.py
python3 5_plot.py
```
