# 🦀 qbeam-rs — Multi-Gigabit Corporate P2P File Transfer (Rust + PyO3 Edition)

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)
[![Rust 2021](https://img.shields.io/badge/Rust-Tokio%20%2B%20Rustls%20%2B%20Rayon-DEA584)](#quick-start)
[![Python Bindings](https://img.shields.io/badge/PyO3-Maturin%20Wheel-3776AB)](#2-python-package-pyo3--maturin)
[![TLS 1.3](https://img.shields.io/badge/Security-TLS%201.3%20%2B%20Pinned%20ECDSA-success)](#security-architecture)

**`qbeam-rs`** is a high-throughput, multi-core **Rust** point-to-point file and directory transfer engine built on `tokio`, `rustls`, `axum`, `reqwest`, `rayon`, and `indicatif`, with optional **PyO3 / Maturin** bindings for the Python ecosystem.

Inspired by **[`uv`](https://github.com/astral-sh/uv)** and its extraordinarily fast Rust-powered package downloader, `qbeam-rs` applies the same **multi-core async concurrency**, **rolling slot-pool terminal UI**, and **cryptographic integrity verification** to direct machine-to-machine file transfers.

Designed for 10GbE–40GbE corporate networks, VLANs, and enterprise VPNs, `qbeam-rs` transfers files directly between Machine A and Machine B over strict **TLS 1.3** with zero external relay or STUN servers.

> 💡 **100% Wire-Compatible with `qbeam` (Python Edition):** A `qbeam-rs` sender can serve files to a pure-Python `qbeam` receiver and vice-versa. Need a zero-compiler single-file PEP 723 Python script? Check out the sister repository: **`qbeam` (`qbeam-py`)**.

---

## ⚡ Why `qbeam-rs`?

- **Multi-Core Work-Stealing Async I/O (`tokio`)**: Saturates 10GbE–40GbE NICs across all CPU cores with zero Python GIL overhead.
- **Parallel Directory Walk & SHA-256 Hashing (`rayon` + `sha2`)**: Hashes multi-gigabyte directories across all CPU cores simultaneously on startup.
- **Custom Rustls Certificate Pinning (`PinnedCertVerifier`)**: Enforces constant-time (`subtle::ConstantTimeEq`) SHA-256 certificate fingerprint verification directly inside the TLS 1.3 handshake.
- **3-Tier `uv`-Style Concurrent Engine**:
  - **Tier 1 (`<= 128 KiB`)**: Multiplexed binary batch streaming (`POST /batch`).
  - **Tier 2 (`128 KiB – 16 MiB`)**: LPT-ordered concurrent file workers with `.qbeam.part` HTTP `Range` auto-resume.
  - **Tier 3 (`>= 16 MiB`)**: Striped `8 MiB` parallel multi-Range segments across worker slots with `.qbeam.meta` crash recovery.
- **Lock-Free Terminal UI (`indicatif`)**: Atomic progress counters (`MultiProgress`) with zero lock contention.

---

## 🚀 Quick Start

### 1. Native Rust CLI Binary
```bash
# Machine A (Sender)
cargo run --release -- serve ./my_packages

# Output:
# Ready! Serving 142 files (1850.40 MB) over TLS 1.3 (SHA-256 Verified)
# Run this on Machine B:
#   qbeam-rs pull 10.24.8.15:8443:9f8e2b4a1c3d7e0f:xK9mP2vL_8qW1zR4nB7jCw

# Machine B (Receiver - default 15 concurrent workers, optional -o output directory)
cargo run --release -- pull 10.24.8.15:8000:9f8e2b4a1c3d7e0f:xK9mP2vL_8qW1zR4nB7jCw -o ./downloads -w 15
```

### 2. Python Package (`PyO3` + `Maturin`)
Build and install the native Rust extension into Python:
```bash
uvx maturin build --release
```

Use from Python (all Rust threads run with the Python GIL released via `py.allow_threads`):
```python
import qbeam_rs

# Machine A (Sender)
qbeam_rs.serve("./my_packages", port=8443)

# Machine B (Receiver)
qbeam_rs.pull("10.24.8.15:8443:9f8e2b4a1c3d7e0f:xK9mP2vL_8qW1zR4nB7jCw", concurrency=15, dest=".")
```

---

## 🔒 Security Architecture

1. **In-Memory Ephemeral ECDSA P-256 TLS 1.3**:
   - Generated on startup via `rcgen` (never touches disk) and locked strictly to `&rustls::version::TLS13`.
2. **Handshake-Level Certificate Pinning**:
   - `PinnedCertVerifier` implements `rustls::client::danger::ServerCertVerifier`, verifying the 16-character SHA-256 DER digest in constant time and cryptographically validating the TLS 1.3 signature via `ring`.
3. **Constant-Time Bearer Token & SHA-256 Verification**:
   - Enforced via `subtle::ConstantTimeEq` across `/manifest`, `/file`, and `/batch`.
4. **Canonical Path Sandboxing**:
   - Rejects `..`, root prefixes, and symlink escapes outside `base_dir`.

---

## 🧪 Running Tests

```bash
cargo test
```

## 🙏 Inspiration & Acknowledgments

- **[`uv` (by Astral)](https://github.com/astral-sh/uv)**: Directly inspired `qbeam-rs`'s Rust + `tokio` + `indicatif` concurrent download architecture, rolling worker pool UX, and PyO3/Maturin packaging model.
- **[`sendme` (by n0 / Iroh)](https://github.com/n0-computer/sendme)**: Inspired the single copy-paste connection ticket (`IP:PORT:CERT_FP:TOKEN`), re-engineered here over point-to-point TCP + TLS 1.3 for strict corporate firewall compatibility.

## 📄 License

BSD 3-Clause ("New" or "Revised") License — see [LICENSE](LICENSE).
