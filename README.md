# Chronos-Track: Remote Hardware Fingerprinting Tool (PoC)

Chronos-Track is a low-level Rust proof-of-concept that fingerprints remote hardware by estimating the microscopic clock skew of a device's quartz oscillator. The tool passively sniffs TCP traffic, leverages Linux kernel timestamping (SO_TIMESTAMPING), and applies a convex-hull jitter filter to approximate the true one-way delay drift between systems.

## Key Features
- **Passive TCP timestamp fingerprinting** – operates on raw sockets and never injects traffic.
- **Linux SO_TIMESTAMPING integration** – captures high-precision RX timestamps directly from the kernel to avoid user-space jitter.
- **Convex hull latency filtering** – uses a monotone-chain lower hull to remove transient network jitter before estimating slope/ppm skew.

## Quick Start
```bash
# Build optimized binary
cargo build --release

# Run with debugging enabled (requires CAP_NET_RAW or sudo)
RUST_LOG=debug sudo -E ./target/release/chronos_track \
    --interface eth0 \
    --target-ip 203.0.113.42
```

`measurements.csv` will contain streaming pairs of kernel receive times and remote TCP timestamp values for offline analysis.

## Disclaimer
This software is provided for educational and research purposes only. Use it responsibly and only on networks/hosts where you have explicit authorization.
