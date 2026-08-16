# AutoCrack

**AutoCrack** is an automated Wi-Fi security auditing tool designed to streamline the process of capturing WPA/WPA2 handshakes and performing dictionary attacks. It orchestrates the underlying `aircrack-ng` suite, managing state transitions, network isolation, and multi-threaded cracking workloads within a unified execution context.

> **Disclaimer:** This tool is provided for educational and authorized security auditing purposes only. Ensure you have explicit permission to audit any network you target. The authors are not responsible for any misuse or damage caused by this software.

## Architecture & Features

- **Automated Dependency Resolution**: Proactively verifies and installs required dependencies (`aircrack-ng`, `wget`) and provisions the `rockyou.txt` dictionary if absent.
- **Resource-Optimized Cracking**: Pre-processes and sanitizes the dictionary payload (filtering for strings ≥ 8 characters) and leverages all available CPU cores to maximize hash rate throughput.
- **Stateful Network Management**: Handles the transition of network interfaces into monitor mode, manages deauthentication payloads, and automatically organizes captured `.cap` files and logs into isolated directories (`data/<SSID>`).
- **Unattended Execution**: After initial target selection, the tool autonomously manages the packet capture (PCAP) lifecycle, payload injection, and the subsequent decryption phase.

## Prerequisites

- Linux operating system
- `go` toolchain (1.x+)
- Root (`sudo`) privileges (required for interface state modification and packet injection)

## Installation

Compile the binary using the Go toolchain:

```bash
# Build the executable
go build -o autocrack
```

## Usage

Execution requires elevated privileges to manipulate network interfaces and inject 802.11 frames.

```bash
sudo ./autocrack
```

### Execution Pipeline

1. **Interface Binding**: The tool prompts for the target wireless interface (e.g., `wlan0`, `wlp1s0`).
2. **Reconnaissance Phase**: Transitions the interface to monitor mode and performs a 15-second active scan.
3. **Target Selection**: Enumerates discovered BSSIDs and prompts for target selection via standard input.
4. **Exploitation Phase**:
   - Initiates asynchronous packet capture on the target's channel.
   - Broadcasts deauthentication frames to force client re-association.
   - Listens for the EAPOL 4-way handshake.
5. **Decryption Phase**: Upon successful capture, spawns a multi-threaded `aircrack-ng` process against the sanitized dictionary.

## Post-Execution System State

**Important:** To ensure clean packet capture without host OS interference, AutoCrack terminates the `NetworkManager` daemon. This leaves the host in an isolated network state post-execution. 

To restore standard network connectivity and interface management, restart the daemon:

```bash
sudo systemctl start NetworkManager
```