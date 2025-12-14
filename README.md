````markdown
# 🕰️ Chronos-Track
### Active Remote Physical Device Fingerprinting Engine

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Language](https://img.shields.io/badge/lang-Rust_1.7+-orange?logo=rust)
![Architecture](https://img.shields.io/badge/arch-x86__64_%7C_aarch64-blueviolet)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/release-v1.2-purple)

> **"Hardware never lies."**

**Chronos-Track** is a specialized active reconnaissance tool that pierces the veil of virtualization. By analyzing microscopic deviations in TCP timestamp frequencies (Clock Skew), it determines if a remote target is a physical machine powered by a quartz crystal or a virtualized honeypot.

Unlike traditional fingerprinting (Nmap/p0f) which looks at static software headers, Chronos-Track measures the **physics of the hardware itself**.

---

## ⚡ Key Capabilities (v1.2)

| Feature | Description |
| :--- | :--- |
| **Active Hunter Mode** | Autonomous Layer-3 injection engine. No dependency on `curl` or `nmap`. |
| **👻 Stealth Jitter** | Randomized packet transmission ($200ms \pm 50ms$) to evade IDS/IPS pattern detection. |
| **🧠 Internal Math Core** | Pure Rust implementation of **Iterative Lower-Bound Regression**. Filters network jitter in real-time. |
| **🛡️ Kernel Bypass** | `RstGuard` module dynamically manipulates `iptables` to suppress OS interference during half-open handshakes. |
| **Scientific Forensics** | Outputs precise **PPM (Parts Per Million)** skew and **Linearity ($R^2$)** metrics. |

### Why This Matters
- **Hardware truthing:** Identifies physical endpoints hiding behind VPNs, Tor exits, or cloud NAT by measuring their crystal oscillator signature.
- **Honeypot detection:** Differentiates real bare-metal from instrumented traps that recycle virtual timestamps.
- **Attribution aid:** Pairs low-level timing data with higher-layer intel to improve clustering of adversary infrastructure.

---

## 🔬 Theory of Operation

Every physical computer relies on a quartz crystal oscillator to keep time. These crystals are imperfect; their actual frequency ($f_{actual}$) deviates slightly from the nominal frequency ($f_{nominal}$) due to manufacturing tolerances and temperature.

**The Clock Skew ($\alpha$)** is defined as:

$$\alpha = \frac{f_{actual} - f_{nominal}}{f_{nominal}}$$

Chronos-Track exploits the **TCP Timestamp Option (RFC 7323)**. By sending periodic probes and recording the target's response timestamps ($T_{ts}$) against our local monotonic clock ($t_{rx}$), we can plot the drift.

* **Physical Hardware:** Shows a stable, linear drift ($R^2 > 0.999$).
* **Virtual Machines:** Show erratic behavior, "steps" in time, or perfect synchronization (0 PPM) due to hypervisor scheduling.

### Data Products
- `measurements.csv` – Raw tuples `(kernel_rx_time_ns, tcp_tsval, src_ip)` for offline research.
- `graphs/*.png` – Optional Python/Matplotlib renders of convex-hull regression for reports.
- **Exit Report** – On `Ctrl+C` the tool prints slope, ppm, R², and verdict for immediate triage.

---

## 🛠️ System Architecture

```mermaid
graph TD;
    A[Injector Tx] -->|Raw SYN + Jitter| B(Target Host);
    B -->|SYN-ACK + TSval| C[Sniffer Rx];
    C -->|Kernel Timestamp| D{Analysis Core};
    D -->|Data Tuple| E[Iterative Regression];
    E -->|Filter Noise| F[Verdict: Physical/Virtual];
````

### The Pipeline

1.  **Injector:** Bypasses standard networking stack to inject crafted packets.
2.  **RstGuard:** Prevents the local kernel from sending `RST` packets that would kill the connection.
3.  **Sniffer:** Uses `AF_PACKET` with `SO_TIMESTAMPING` to grab packet arrival times at the kernel driver level (nanosecond precision), eliminating userspace lag.
4.  **Math Engine:** Calculates the convex hull lower-bound to ignore network lag spikes.
5.  **Reporter:** Streams CSV + emits real-time logs every 50 samples and a final exit verdict.

-----

## 📊 Proof of Concept

> **Figure 1:** Analysis of a physical Linux server. The red regression line indicates a stable hardware clock drift, distinct from the noise floor.

-----

## 🚀 Usage

### Prerequisites

  - Linux kernel with `AF_PACKET` + `SO_TIMESTAMPING` (native or WSL2).
  - `iptables`, `ethtool` (recommended).
  - CAP\_NET\_RAW or root privileges.

### 1\. Build

```bash
cargo build --release
```

### 2\. Prepare Environment (Linux/WSL)

Disable checksum offloading to ensure raw packets are processed correctly by virtual NICs.

```bash
sudo ethtool -K eth0 tx off rx off
```

### 3\. Run Active Scan

```bash
# Run with info logs to see the verdict
RUST_LOG=info sudo -E ./target/release/chronos_track \
    --interface eth0 \
    --target-ip <TARGET_IP>
```

### 4\. Interpret Results

Wait for \~60 seconds and press `Ctrl+C`.

```text
=== Chronos-Track Exit Report ===
Slope: 993.73 Hz        <-- Detected Frequency
Clock Skew: -62.3 ppm   <-- Hardware Deviation
R²: 0.9996              <-- Linearity (Stability)
Verdict: Physical       <-- Conclusion
=================================
```

-----

## 🗺️ Roadmap to v2.0 (Mass Scanner)

Research is complete for the next phase: **Mass Subnet Scanning**.
We are moving from a synchronous architecture to a fully **Asynchronous (Tokio) Monolith** capable of scanning `/16` networks.

  * [x] **v1.2:** Single Target, Stealth Mode, Rust Math.
  * [ ] **v2.0:** Async Tokio Engine, DashMap State Management, Masscan-like throughput.

📄 **[Read the Architecture Design Document](https://www.google.com/search?q=./architecture_v2.pdf)**

-----

## 🤝 Contributing

Pull requests are welcome for:

  - Additional timestamp parsers (QUIC, ICMP).
  - Dashboards / notebooks for post-processing.
  - Hardening for containers (AppArmor/SELinux profiles).

Please open an issue before large-scale refactors so we can coordinate.

## ⚠️ Disclaimer

This tool is designed for **defensive security research** and educational purposes only (e.g., identifying honeypots on your own network).
Scanning third-party infrastructure without permission is illegal and unethical. The authors claim no responsibility for unauthorized use.

```
```