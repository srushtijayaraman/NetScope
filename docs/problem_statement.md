# NetScope: Problem Statement & Academic Motivation

## 1. Introduction & Context
Modern computer networks operate at high data rates, carrying diverse protocols across heterogeneous distributed systems. Network administrators, security engineers, and computer networking students routinely capture raw network packets using packet sniffers. However, raw packet capture dumps (such as `.pcap` or `.pcapng` files) present major cognitive and operational challenges:
- High volume of unstructured binary and hexadecimal frames.
- Difficulty in isolating specific transport flows and multi-layer protocol sequences.
- Manual correlation overhead when computing aggregate network health metrics (e.g., bandwidth throughput, packets-per-second, and inter-arrival duration).
- Lack of immediate visibility into anomalous traffic patterns such as TCP SYN floods or reconnaissance port scanning.

## 2. Problem Statement
There is a pressing educational and operational need for a lightweight, modular, and locally hostable traffic analysis platform that:
1. Ingests raw packet captures (`.pcap` / `.pcapng`) offline and processes live network streams in real time.
2. Accurately decodes and normalizes protocol layers across Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS.
3. Computes mathematically verified traffic analytics (throughput in bps/kbps/Mbps, packet rates, protocol shares, and top talkers) without loss of precision.
4. Detects stateful transport-layer anomalies via explainable rule heuristics.
5. Surfaces traffic intelligence through an interactive, zero-dependency, dark-mode web dashboard.

## 3. Academic Relevance
In an undergraduate or graduate Computer Networks laboratory curriculum, students frequently treat networking protocols as abstract textbook specifications. NetScope bridges the gap between theoretical OSI/TCP-IP models and real-world network packet behavior:
- Demonstrates Layer 2 to Layer 7 encapsulation and field-level decoding.
- Clarifies the mathematical relationship between wire bytes, capture timestamps, and bandwidth throughput.
- Enforces strict classification principles (e.g., verifying payloads rather than guessing protocols based on port numbers alone).
- Provides deterministic verification procedures against industry-standard packet analyzers (Wireshark / TShark).
