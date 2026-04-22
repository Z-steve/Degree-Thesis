# SDS Benchmarking Suite

This folder contains automated scripts designed to test the performance impact of the Scan Detection System (SDS). Because the SDS runs in Python, intercepts packets via `iptables`, and maintains a stateful hash table, it will inherently introduce some latency and potentially cap max throughput.

These scripts allow you to measure exactly how much overhead is introduced.

## Setup Instructions

These scripts should be run from **VM1 (The Benign Client)**.

First, ensure you have the required testing tools installed on VM1:
```bash
sudo apt update
sudo apt install dnsutils curl iperf3
```

Make sure the scripts are executable:
```bash
chmod +x run_latency_tests.sh
chmod +x run_throughput_test.sh
```

## How to properly test

To get scientific, accurate data for your research, you must run these tests twice:

### Phase 1: Baseline (SDS OFF)
1. On VM3 (Gateway), ensure IP forwarding is enabled but the **Python SDS script is stopped**.
2. Flush any iptables rules that redirect traffic to the NFQUEUE:
   `sudo iptables -F`
3. Run the tests on VM1 and record the results.

### Phase 2: SDS Enabled (SDS ON)
1. On VM3, start the Python SDS script (`sudo python3 run.py`).
2. Run the tests on VM1 and record the results.
3. **Compare Phase 1 and Phase 2**.

---

## The Scripts

### 1. Latency & Connection Setup (`run_latency_tests.sh`)
This script tests two things:
- **DNS Resolution Time:** How long it takes to get an IP from a domain (tests the overhead of the SDS modifying the TTL and recalculating the checksum).
- **TCP Connection Setup (TTFB):** How long it takes to establish a TCP handshake (tests the overhead of the SDS checking the hash table for a valid connection).

**Usage:**
```bash
./run_latency_tests.sh
```

### 2. Maximum Throughput (`run_throughput_test.sh`)
This script tests raw bandwidth to see if the Python script becomes a bottleneck under heavy load.
*Note: You need a machine outside the internal network (e.g., your Host Machine, or a 4th VM) to act as the server.*

**Usage:**
1. On the external machine, start the server:
   ```bash
   iperf3 -s
   ```
2. On VM1, run the client against the server's IP:
   ```bash
   ./run_throughput_test.sh <EXTERNAL_SERVER_IP>
   ```
