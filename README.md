# protofire
![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange)
![ICS Protocols: Modbus/DNP3/S7/IEC104/OPCUA](https://img.shields.io/badge/ICS%20Protocols-Modbus%2FDNP3%2FS7%2FIEC104%2FOPCUA-blue)
![Air-Gapped Compatible](https://img.shields.io/badge/Offline-Airgapped%20Safe-green)
![CI Safety Mode](https://img.shields.io/badge/CI%20Testing-Safe-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)
![Critical Infrastructure Research](https://img.shields.io/badge/Use-OT%20Security%20Research-red)

protofire is a modular, multi-protocol fuzzer targeting Industrial Control System (ICS) and Operational Technology (OT) protocols. Designed for red team operators, fuzzing researchers, and security engineers working with ICS/SCADA environments.

> `protofire` is in **alpha** — use at your own risk. Expect bugs, instability, and rapid changes.  
> Ideal for **red team experiments**, and **industrial protocol research**.

## Legal & Safety Notice 

Use ONLY on:

Systems you own

Dedicated testbeds

Targets with explicit written authorization

Improper use risks service disruption affecting:

Power grids

Water utilities

Transportation

Manufacturing safety

You - the operator - assume all responsibility.

### MITRE ICS ATT&CK Mapping

| Behavior Category | Technique Name | Technique ID | Domain |
|------------------|----------------|--------------|--------|
| Malformed industrial payloads | Manipulation of Control | T0820 | ICS |
| Protocol corruption causing faults | Denial of Control | T0814 | ICS |
| Abnormal data forcing actuation | Signal Manipulation | T0831 | ICS |
| Runtime crashes via parsing errors | Damage to Peripherals | T0866 | ICS |
| PCAP replay traffic mutation | Spoof Reporting Messages | T0886 | ICS |
| Field boundary violations | Exploit Capabilities | T0828 | ICS |


## Features
- Modular plugin-based protocol fuzzing
  - Supports:
    - Modbus/TCP
    - DNP3
    - S7comm
    - IEC 60870-5-104
    - OPC UA
- Mutation strategies:
  - Random bit flipping
  - Overflow injection
  - Dictionary-based input
  - Format string injection
  - Type confusion
  - Time-based values
  - Sequence violations
- PCAP input/output support
- Stateful fuzzing (e.g., tracking transaction/session IDs)
- Multi-threaded fuzzing engine
- Replay mode from PCAP files
- Anomaly, crash, and timeout logging

## Architecture Overview
```
protofire/
├── fuzzer.c                  # Main logic, CLI interface, and thread controller
├── fuzzer_protocol.h         # Protocol module interface definition
├── fuzzer_protocol_common.c # Common utilities for all protocol handlers
├── grammar_fieldmap.h        # Field mapping stub for future grammar-based mutations
├── plugins/
│   ├── modbus_module.c       # Modbus fuzzing plugin
│   ├── dnp3_module.c         # DNP3 fuzzing plugin
│   ├── s7comm_module.c       # Siemens S7Comm fuzzing plugin
│   ├── iec104_module.c       # IEC 60870-5-104 fuzzing plugin
│   ├── opc_ua_module.c       # OPC UA fuzzing plugin
├── crashes/                  # Saved payloads that triggered crashes
├── logs/                     # Execution and error logging
├── Makefile                  # Build automation script
├── protofire                 # Compiled fuzzer binary (output)
└── README.md                 # Project documentation
```
Build Instructions

Dependencies:
- gcc
- libpcap-dev
- make
- pthread

To build everything:
```bash
make
```
Usage
```bash
./protofire -t <IP> -P <PORT> -p <protocol> [options]
```
### Command-Line Options

```
  -t <ip>             Target IP address

  -P <port>           Target port (optional, auto-set based on protocol)

  -p <protocol>       Protocol to fuzz:
                        modbus, dnp3, s7, iec104, opcua

  -s <strategy>       Mutation strategy:
                        random, bitflip, overflow, dictionary,
                        format, type, time, sequence

  -i <iterations>     Number of fuzzing iterations

  -T <threads>        Number of threads to use

  -S                  Enable stateful fuzzing (e.g., session tracking)

  -R <file.pcap>      Record all sent packets to a PCAP file

  -r <file.pcap>      Replay packets from an existing PCAP

  -d <ms>             Delay (in milliseconds) between packets

  -v                  Enable verbose logging
```
Example:
```bash
./protofire -t 192.168.1.10 -p modbus -s dictionary -i 5000 -T 8 -R fuzz_run.pcap
```
### Fuzzing Strategies

```
random     – random byte mutations

bitflip    – single-bit flips

overflow   – fill fields with 0xFF (overflow testing)

dictionary – inject protocol-specific invalid codes and edge-case values

format     – format string injection (e.g., %x%n, %s)

type       – type confusion between float and int

time       – inject maximum timestamp values (e.g., 0xFFFFFFFFFFFFFFFF)

sequence   – force protocol into out-of-order or invalid state transitions
```
### Protocol Coverage

Modbus/TCP
- Mutation of function codes and quantity fields
- Handles MBAP header length recalculation

DNP3
- Field flips and CRC recalculation
- Field size-aware mutation

S7comm
- Mutation of PDU fields and protocol identifiers

IEC 60870-5-104
- ASDU type mutation and checksum recalculation

OPC UA
- Mutation of headers and message types
- Includes format string injection potential

### Output Logging
- logs/ contains runtime logs and anomaly detection
- crashes/ contains payloads that triggered unexpected behavior
- If -R is enabled, PCAP output is saved

### Replay Mode

You can fuzz by mutating captured traffic using:  
```bash
./protofire -r input.pcap -t 192.168.1.100 -p modbus -s bitflip
```
This enables a semi-black-box fuzzing strategy using prior traffic.

### Extending Protocols

To add a new protocol:
1. Create a new plugin source file plugins/newproto_module.c
2. Implement the fuzzer_protocol.h interface
3. Add a libprot_newproto.so target in the Makefile
4. Register the new protocol in fuzzer.c with a proper enum and handler
The plugin system is designed to be minimal, self-contained, and portable.


License
------------------------

This project is licensed under the [MIT License](LICENSE).

<!--
SEO FOOTER — ICS/SCADA PROTOCOL FUZZING TOOLKIT

Description:
Advanced fuzzing and anomaly discovery tool for ICS/OT cyber-physical systems including Modbus, DNP3, S7comm, IEC104, OPC-UA. Enables secure validation of industrial automation and critical infrastructure resilience.

Primary Search Keywords:
ICS cybersecurity, SCADA protocol fuzzer, industrial control system testing, OT red team tools, Siemens S7 exploitation research, Modbus penetration testing, DNP3 fuzzing engine, OPC-UA fuzzing, critical infrastructure cyber defense, PLC fuzzing tools, PCAP replay, industrial protocol mutation, grid security, water treatment plant cybersecurity, manufacturing automation safety tests

Secondary Search Keywords:
stateful protocol fuzzing, cyber-physical anomaly testing, control safety validation, industrial protocol security scanner, secure fuzz harness for operational technology, ICS network simulation red team, 61850 alternative analysis

Target Audience:
OT security engineers, ICS researchers, Red/Blue team operators, industrial automation defenders, power utility cybersecurity teams, ICS/SCADA labs and universities.

Purpose:
Maximize GitHub discoverability and CSIRT lab adoption; protect critical infrastructure by exposing exploitable protocol behavior before adversaries do.
-->


> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.
