# injspoof

A high-performance raw packet proxy that tunnels UDP traffic through spoofed source IP addresses. Operates at Layer 2 (Ethernet frame level) for maximum throughput, supporting both TCP and UDP obfuscation protocols with configurable IP-level fragmentation.

## Architecture

```
┌──────────┐    UDP     ┌────────────────┐   raw L2    ┌────────────────┐    UDP     ┌──────────┐
│  Local   │ ────────→  │   injspoof     │ ──────────→ │   injspoof     │ ────────→  │ Backend  │
│   App    │            │   (client)     │  spoofed    │   (server)     │            │  Server  │
│          │ ←────────  │                │  src IP     │                │ ←────────  │          │
└──────────┘   return   └────────────────┘   ←──────── └────────────────┘   return   └──────────┘
              traffic         ↑                              ↑              traffic
                         raw socket                     raw socket
                         AF_PACKET                      AF_PACKET
```

**Client mode**: Receives UDP from a local application, wraps it in a raw Ethernet frame with a spoofed source IP, and sends it to the remote server.

**Server mode**: Captures incoming raw packets on a specific interface, extracts the payload, and forwards it to a local backend. Responses from the backend are sent back through the raw tunnel with a spoofed source.

## Build

```bash
# Release build (optimized, -O2 -march=native -flto)
make

# Debug build (includes LOG_DEBUG output, no -Werror)
make DEBUG=1

# Install to /usr/local/bin
sudo make install

# Clean
make clean
```

**Requirements**: Linux, GCC, root privileges (or `CAP_NET_RAW`)

```bash
# Alternative to running as root — grant raw socket capability:
sudo setcap cap_net_raw+ep ./injspoof
```

## Usage

```bash
sudo ./injspoof --mode client --config client.json
sudo ./injspoof --mode server --config server.json
```

## Configuration

### Client (`client.json`)

```json
{
    "listen": {
        "address": "127.0.0.1",
        "port": 8080
    },
    "connect": {
        "to": {
            "address": "[PUBLIC_IP]",
            "port": 5050
        },
        "with": {
            "source": {
                "address": {
                    "type": "static",
                    "value": [
                        "2.188.21.42",
                        "2.188.21.41"
                    ]
                },
                "port": [443]
            }
        },
        "protocol": {
            "mode": "udp"
        }
    },
    "capture": {
        "interface": "ens160",
        "filter": {
            "source": {
                "address": {
                    "type": "static",
                    "value": ["194.225.101.190"]
                },
                "port": [8443]
            }
        }
    },
    "outgoing": {
        "interface": "ens160",
        "gateway_mac": "xx:xx:xx:xx:xx:xx"
    },
    "tuning": {
        "fragment_size": 1400,
        "ip_selection_strategy": "round_robin"
    }
}
```

### Server (`server.json`)

```json
{
    "forward": {
        "address": "127.0.0.1",
        "port": 8080
    },
    "response": {
        "to": {
            "address": "[PUBLIC_IP]",
            "port": 5008
        },
        "with": {
            "source": {
                "address": {
                    "type": "static",
                    "value": ["194.225.101.190"]
                },
                "port": [8443]
            }
        },
        "protocol": {
            "mode": "udp"
        }
    },
    "capture": {
        "interface": "ens160",
        "filter": {
            "source": {
                "address": {
                    "type": "static",
                    "value": ["2.188.21.42"]
                },
                "port": {
                    "type": "static",
                    "value": [443]
                }
            }
        }
    },
    "outgoing": {
        "interface": "eth0",
        "gateway_mac": "xx:xx:xx:xx:xx:xx"
    },
    "tuning": {
        "fragment_size": 1400,
        "ip_selection_strategy": "round_robin",
        "steal_client_source_ip": false
    }
}
```

### Configuration Reference

| Section | Key | Description |
|---------|-----|-------------|
| `listen` / `forward` | `address`, `port` | Local UDP endpoint. Client listens here; server forwards here. |
| `connect.to` / `response.to` | `address`, `port` | Remote destination for outgoing raw packets. |
| `*.with.source.address` | `type`, `value` | Spoofed source IPs. `"static"`: inline array. `"file"`: path to file with one IP per line. |
| `*.with.source.port` | array or object | Spoofed source ports. |
| `*.protocol` | `mode`, `option.flag` | `"tcp"` or `"udp"`. TCP supports flags like `"psh+ack"`, `"syn"`, `"ack"`. |
| `capture` | `interface`, `filter` | Interface and BPF filter for receiving raw packets. |
| `outgoing` | `interface`, `gateway_mac` | Interface and next-hop MAC for sending raw packets. |
| `tuning.fragment_size` | integer | IP fragmentation threshold in bytes (default: 1400, range: 68–9000). |
| `tuning.ip_selection_strategy` | `"round_robin"` | How to rotate through multiple source IPs. |
| `tuning.steal_client_source_ip` | boolean | **Server only**: use the incoming packet's spoofed source IP as the response source. |

### Source Address Modes

**Static** — Individual IPs and CIDR subnets listed directly in the config. CIDR ranges are processed natively using bitwise math, seamlessly supporting massive networks natively (e.g. limitless `/16` or `/8` ranges) with zero memory overhead.
```json
"address": {
    "type": "static",
    "value": ["1.2.3.4", "5.6.0.0/16"]
}
```

**File** — IPs and CIDR subnets loaded from a text file (one IP/CIDR per line, `#` comments supported).
```json
"address": {
    "type": "file",
    "value": "ips.txt"
}
```

### `steal_client_source_ip`

When enabled on the server, the server captures the spoofed source IP from incoming client packets and uses that same IP as the source for response packets. This means `response.with.source.address` is ignored (only the port is used).

This is useful when the client rotates through multiple source IPs — the server automatically mirrors whichever IP the client used.

## Blocking Harmful Traffic

When injspoof sends raw packets, the kernel doesn't know about the "connection". It will generate unwanted responses:

- **TCP mode**: The kernel sends TCP RST packets (since it has no open TCP socket on that port)
- **UDP mode**: The kernel sends ICMP Destination Unreachable packets (since no socket is listening)

You must suppress this traffic manually using `nftables` or `iptables`.

### Using nftables (Ubuntu 22+/24+)

**Block TCP RST on port 443:**
```bash
sudo nft add table ip injspoof_tcp
sudo nft add chain ip injspoof_tcp output { type filter hook output priority mangle \; }
sudo nft add rule ip injspoof_tcp output tcp sport 443 tcp flags rst / rst drop
```

**Block ICMP unreachable for UDP on port 5008:**
```bash
sudo nft add table ip injspoof_udp
sudo nft add chain ip injspoof_udp output { type filter hook output priority filter \; }
sudo nft add rule ip injspoof_udp output icmp type destination-unreachable drop
```

**Remove rules (cleanup):**
```bash
sudo nft delete table ip injspoof_tcp
sudo nft delete table ip injspoof_udp
```

**Verify rules:**
```bash
sudo nft list tables
sudo nft list table ip injspoof_tcp
```

### Using iptables (legacy)

**Block TCP RST:**
```bash
sudo iptables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
```

**Block ICMP unreachable:**
```bash
sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

**Connection tracking bypass (recommended for performance):**
```bash
sudo iptables -t raw -A PREROUTING -p tcp --dport 443 -j NOTRACK
sudo iptables -t raw -A OUTPUT -p tcp --sport 443 -j NOTRACK
```

## Debugging with nc and tcpdump

### Step 1: Set Up a Test Backend

On the **server** machine, start a simple UDP echo listener:

```bash
# Listen on UDP port 8080 (the forward target)
nc -u -l -p 8080
```

### Step 2: Capture Traffic

On either machine, capture traffic to see what's happening:

```bash
# On the CLIENT — see outgoing spoofed packets
sudo tcpdump -i ens160 -nn -vv "host [PUBLIC_IP] and port 5050"

# On the SERVER — see incoming spoofed packets
sudo tcpdump -i ens160 -nn -vv "host 2.188.21.42 and port 443"

# Capture with hex dump for deep inspection
sudo tcpdump -i ens160 -nn -XX "port 443"
```

### Step 3: Send Test Data

On the **client** machine, send test data into the local UDP listener:

```bash
# Send a test string to the client's listen port
echo "hello injspoof" | nc -u 127.0.0.1 8080
```

### Step 4: Verify the Flow

**What you should see in tcpdump on the client side:**
```
IP 2.188.21.42.443 > [PUBLIC_IP].5050: Flags [P.], seq 0:14, ...
```
This confirms: spoofed source `2.188.21.42:443`, destination `[PUBLIC_IP]:5050`, PSH+ACK flags (`[P.]`).

> **Note on tcpdump flag notation:** The `.` represents ACK. So `[P.]` = PSH+ACK, `[S.]` = SYN+ACK, `[.]` = ACK only.

**What you should see on the server side:**
```
IP 2.188.21.42.443 > <server-ip>.5050: Flags [P.], seq 0:14, ...
```
And in the `nc` terminal, the message `hello injspoof` should appear.

### Step 5: Verify Return Path

Type a response in the server's `nc` terminal. On the server's tcpdump:
```
IP 194.225.101.190.8443 > [PUBLIC_IP].5008: UDP, length 12
```

On the client's tcpdump, you should see the response arriving with the server's spoofed source.

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| No packets on wire | Wrong interface or gateway MAC | Check `outgoing.interface` and `gateway_mac` with `ip link show` and `ip neigh` |
| Packets sent but no response | Kernel sending RST/ICMP | Block with nft/iptables (see above) |
| Filter not matching | Wrong capture filter IPs/ports | Verify `capture.filter` matches the remote's source |
| `Permission denied` | Not running as root | Use `sudo` or `setcap cap_net_raw+ep` |
| Fragmented packets lost | MTU too small or fragment_size wrong | Set `fragment_size` to your path MTU minus ~60 bytes |

### Finding Your Gateway MAC

```bash
# Show the default gateway
ip route show default

# Show all ARP/neighbor entries
ip neigh show

# Example output:
# 192.168.1.1 dev ens160 lladdr xx:xx:xx:xx:xx:xx REACHABLE
#                              ^^^^^^^^^^^^^^^^^ this is your gateway_mac
```

## Performance Notes

injspoof operates at Layer 2 (`AF_PACKET`) for maximum performance:

- **Zero-copy path**: Packets are built directly in userspace buffers and sent via the kernel's packet socket — no IP stack traversal
- **PACKET_QDISC_BYPASS**: Bypasses the kernel's traffic control queueing discipline for lower latency
- **SO_BUSY_POLL**: Reduces receive latency by polling the NIC driver directly
- **Pre-compiled IP filters**: All filter IPs are converted to `uint32_t` at config load time — no string parsing on the hot path
- **Lock-free memory pool**: Atomic CAS-based buffer pool eliminates malloc/free on the hot path
- **Large socket buffers**: 4MB send/receive buffers for burst absorption
- **IP fragmentation**: Configurable RFC 791 fragmentation with proper MF flags and 8-byte alignment

## License

MIT
