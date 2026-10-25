# merlin-otel-agent 🚀📡

> **Disclaimer:** This project was **unapologetically vibe coded** using **Gemini 3.8 Flash** driven by **Google Antigravity**. If you were hoping for a 300 MB enterprise Java telemetry framework with forty abstract factory beans and an XML configuration file, you have wandered into the wrong repository.

`merlin-otel-agent` is an ultra-lean, opinionated OpenTelemetry host daemon cyber-hand-forged in pure C++17 for the **ASUS RT-BE92U** (Broadcom BCM6765 quad-core ARMv8) running **Asuswrt-Merlin**.

It was built specifically to siphon wire-speed telemetry out of the deepest, darkest crevices of Broadcom's proprietary network silicon and slingshot it directly into **[OpenObserve](https://openobserve.ai/)** via OTLP/HTTP (`/api/default/v1/metrics` and `/api/default/v1/logs`).

Statically compiled (`aarch64-linux-musl`) into a single self-contained binary (**~834 KB stripped**, **< 3.5 MB RSS**) with **zero external runtime dependencies**.

---

### Why does this exist? 🧠⚡

1. **The Standard OTel Collector is Too Fat**: The official Go-based OpenTelemetry Collector binary is ~60 MB to 150 MB and hungrily gobbles RAM. If you try running that on an embedded router where memory is fiercely contested by Wi-Fi 7 MLO buffers and hardware packet rings, the Linux OOM-killer will ruthlessly assassinate your Dropbear SSH daemon.
2. **`/proc/net/dev` is a Lie**: On modern Broadcom routers, up to 98% of your traffic never touches the Linux network stack—it vanishes directly into proprietary hardware acceleration engines (**Packet Flow Cache**, **Archer**, and **Runner**) like socks in a laundromat dryer. Standard exporters report your router is virtually idle while you are saturating a 10G fiber pipe.
3. **Because We Can**: Why own a flagship Wi-Fi 7 router if you can't chart your smart fridge's 6 GHz packet bursts in OpenObserve in real-time?

---

## Architecture & Resource Footprint

`merlin-otel-agent` is engineered from the ground up for embedded network appliances:

- **Ultra-Compact Static Binary**: Statically linked against `musl libc`, producing a self-contained **~834 KB** stripped binary that runs on any `aarch64` Linux 4.19+ kernel without external shared libraries.
- **Low Memory Footprint**: Operates stably with **< 3.5 MB RSS** under sustained router load.
- **Zero-Dependency Native HTTP Engine**: Avoids linking massive multi-protocol libraries (such as OpenSSL and cURL) by using a purpose-built, non-blocking raw POSIX TCP HTTP/1.1 client for wire-speed LAN ingestion.
- **Native OTLP Protobuf Wire Encoder**: Encodes metric and log batches directly into memory buffers conforming to the OTLP v1 Protobuf specification without Google `libprotobuf` runtime overhead.
- **Resilient Bounded Ring Buffer**: Employs a non-blocking queue with an exponential-backoff circuit breaker, ensuring that backend ingestion delays or collector downtime never block or destabilize router networking.

---

## Key Features

1. **Broadcom Hardware Offload Reconciliation**:
   - Collects and aggregates statistics across multiple layers:
     - Linux kernel network interfaces (`/proc/net/dev`, `/sys/class/net/*`)
     - Broadcom Packet Flow Cache (`/proc/fcache/*`, `fcctl`)
     - Broadcom Archer / Runner hardware acceleration engine (`/proc/archer/stats`, `archer stats`)
     - Physical switch MAC MIB counters via `ioctl(SIOCETHTOOL)` / `ethctl stats` for true wire-level byte throughput.
2. **Wi-Fi 7 & Tri-Band Radio Telemetry**:
   - Gathers per-radio metrics for 2.4 GHz, 5 GHz, and 6 GHz bands (`wl0`, `wl1`, `wl2`, plus virtual guest BSSIDs):
     - Channel utilization, interference, and noise floor
     - Associated client counts
     - Per-station PHY rates, bandwidth capabilities, and RSSI
3. **In-Process Netlink Connection Tracking**:
   - Direct netlink socket subscription to `NFNLGRP_CONNTRACK_DESTROY` multicast events.
   - Automatically buckets high ephemeral ports (e.g., port 32768–65535 into bucket `32768+`) to bound metric cardinality while retaining high-visibility services (DNS, HTTPS, SSH, WireGuard, Steam, etc.).
   - Classifies internal LAN subnets (configurable via `lan_subnets`) to identify top local talkers without memory leaks.
4. **Rotation-Safe Syslog Ingestion**:
   - Monitors `/tmp/syslog.log` in RAM using inode and file-offset tracking.
   - Handles log file rotation (e.g., rollover to `syslog.log-1`) and truncation transparently without losing log lines.
   - Parses BSD/Merlin syslog headers (`app`, `pid`, timestamp, severity) and streams them to the OTLP `/v1/logs` endpoint.
   - Built-in token-bucket rate limiter protects against Wi-Fi deauth/logging storms.
5. **Host & System Health**:
   - Quad-core CPU utilization (user, system, nice, iowait, irq).
   - Detailed memory breakdown (total, free, available, buffers, cached, slab).
   - Load averages (1m, 5m, 15m), process count, and `/jffs` flash storage utilization.

---

## Directory Structure

```text
merlin-otel-collector/
├── CMakeLists.txt              # CMake build configuration
├── Dockerfile                  # Multi-stage aarch64 build, test & security scan
├── Makefile                    # Make targets: make test, make export, make scan
├── deploy.ps1                  # Automated deployment script for Asuswrt-Merlin
├── config/
│   ├── motel.conf.example      # Annotated configuration file template
│   └── services-start          # Asuswrt-Merlin boot init hook script
├── include/
│   ├── Config.h                # INI configuration parser & schema
│   ├── collectors/             # Telemetry collector interfaces & definitions
│   │   ├── Collector.h
│   │   ├── HostMetricsCollector.h
│   │   ├── NetInterfaceCollector.h
│   │   ├── BcmFlowCacheCollector.h
│   │   ├── BcmArcherCollector.h
│   │   ├── BcmWifiCollector.h
│   │   ├── SyslogTailer.h
│   │   └── NetlinkConntrackCollector.h
│   ├── otel/                   # OTLP wire encoder, metrics & sender definitions
│   │   ├── OtelDefaults.h
│   │   ├── OtelProtoEncoder.h
│   │   ├── OtelMetrics.h
│   │   ├── OtelLogger.h
│   │   └── OtelSender.h
│   └── platform/               # IP classification & subprocess execution
│       ├── IpClassifier.h
│       ├── StringUtils.h
│       └── SubprocessRunner.h
├── src/
│   ├── Config.cpp
│   ├── main.cpp                # Daemon entry point, scheduler & signal handling
│   ├── collectors/             # Telemetry collector implementations
│   ├── otel/                   # Protobuf encoder & HTTP sender implementation
│   └── platform/               # Subprocess runner & IP classifier implementation
└── tests/
    └── test_collectors.cpp     # Comprehensive unit tests with mocked router data
```

---

## Configuration

The agent is configured via `/jffs/etc/motel.conf` (or via `-c /path/to/motel.conf`).

Key configuration settings:

| Setting | Default | Description |
| :--- | :--- | :--- |
| `endpoint` | `http://192.168.1.100:4318` | Target OTLP/HTTP endpoint (e.g. OpenObserve or OTel Collector) |
| `headers` | *(empty)* | Optional HTTP headers (e.g. `Authorization=Basic <TOKEN>`, `X-Scope-OrgID=default`) |
| `scrape_interval_sec` | `15` | Fast scrape interval for CPU, memory, network interfaces, and Flow Cache |
| `slow_interval_sec` | `60` | Slow scrape interval for Wi-Fi station tables and NVRAM status |
| `lan_subnets` | `192.168.0.0/16, 10.0.0.0/8` | Local LAN subnets used to identify internal clients in flow accounting |
| `enable_host` | `1` | Enable CPU, memory, load average, and disk usage metrics |
| `enable_net` | `1` | Enable interface throughput and switch MAC MIB counters |
| `enable_flowcache` | `1` | Enable Broadcom Packet Flow Cache acceleration stats |
| `enable_archer` | `1` | Enable Broadcom Archer hardware engine stats |
| `enable_wifi` | `1` | Enable Wi-Fi 7 channel utilization and associated client stats |
| `enable_conntrack_events`| `1` | Enable in-process Netlink connection tracking traffic accounting |
| `enable_syslog` | `1` | Enable real-time `/tmp/syslog.log` tailing and streaming |
| `syslog_rate_limit` | `50.0` | Maximum sustained syslog entries forwarded per second |
| `queue_capacity` | `128` | Max queued telemetry payloads in memory ring buffer |

Refer to [`config/motel.conf.example`](config/motel.conf.example) for a fully annotated template.

---

## Building the Static Binary

Building requires Docker with BuildKit enabled.

### 1. Run Unit Tests Under QEMU:
```bash
make test
# Or with Docker directly:
docker buildx build --target test --progress=plain .
```
Executes all unit tests under `linux/arm64` QEMU emulation against mock Broadcom and Linux kernel fixtures.

### 2. Export the Static `aarch64` Binary:
```bash
make export
# Or with Docker directly:
docker buildx build --target export --output dist .
```
The resulting stripped static binary is written to `./dist/merlin-otel-agent`.

### 3. Static Security Analysis:
```bash
make scan
# Or with Docker directly:
docker buildx build --target security-scan --progress=plain .
```
Runs automated security auditing across the codebase:
- **`cppcheck`**: Memory bounds, null pointer dereferences, uninitialized memory, and leaks.
- **`clang-tidy`**: AST-level checks targeting CERT C++ rules, `bugprone-*`, and `clang-analyzer-security.*`.
- **`flawfinder`**: CWE vulnerability scanning.

---

## Deployment on Asuswrt-Merlin

> [!NOTE]
> Dropbear SSH on Asuswrt-Merlin does not include the SFTP subsystem by default. Use `-O` for legacy SCP mode.

### Option A: Using the PowerShell Deployment Script
```powershell
.\deploy.ps1 -RouterIp "192.168.1.1" -Port 22 -User "admin"
```
Or via `make`:
```bash
make deploy ROUTER_IP=192.168.1.1 ROUTER_PORT=22 ROUTER_USER=admin
```

### Option B: Manual SSH / SCP Commands
1. **Ensure target directories exist on `/jffs`**:
   ```bash
   ssh -p 22 admin@192.168.1.1 "mkdir -p /jffs/bin /jffs/etc /jffs/scripts"
   ```

2. **Copy binary, configuration, and startup script**:
   ```bash
   scp -O -P 22 dist/merlin-otel-agent admin@192.168.1.1:/jffs/bin/merlin-otel-agent
   scp -O -P 22 dist/motel.conf.example admin@192.168.1.1:/jffs/etc/motel.conf
   scp -O -P 22 dist/services-start admin@192.168.1.1:/jffs/scripts/services-start
   ```

3. **Set executable permissions**:
   ```bash
   ssh -p 22 admin@192.168.1.1 "chmod +x /jffs/bin/merlin-otel-agent /jffs/scripts/services-start"
   ```

4. **Edit `/jffs/etc/motel.conf`** with your collector endpoint:
   ```bash
   nano /jffs/etc/motel.conf
   ```

5. **Start the daemon**:
   ```bash
   ssh -p 22 admin@192.168.1.1 "/jffs/scripts/services-start"
   ```
   Check router syslog for startup confirmation:
   ```bash
   ssh -p 22 admin@192.168.1.1 "logread | grep motel"
   ```

---

## License & Acknowledgements

`merlin-otel-agent` is released under the [MIT License](LICENSE).

### Third-Party Credits:
- **[otel-embedded-cpp](https://github.com/proffalken/otel-embedded-cpp)**: Core inspiration for embedded C++ OpenTelemetry APIs by [Matt Jarvis (@proffalken)](https://github.com/proffalken), licensed under the MIT License. Adapted into pure C++17 without Arduino/Nanopb dependencies.
- **[OpenTelemetry Protocol](https://github.com/open-telemetry/opentelemetry-proto)**: Protobuf schema specifications and wire semantics by The OpenTelemetry Authors (Apache License 2.0).
- **[OpenObserve](https://github.com/openobserve/openobserve)**: Cloud-native observability platform by Quickwit, Inc. and contributors.
- **[Asuswrt-Merlin](https://github.com/RMerl/asuswrt-merlin.ng)**: Custom router firmware by Eric Sauvageau (RMerl) and ASUSTeK Computer Inc.
