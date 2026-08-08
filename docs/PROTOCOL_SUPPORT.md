# Protocol and Capture Support

## Link layers

| DLT | Support |
|---|---|
| 0 BSD NULL | IPv4/IPv6 family dispatch |
| 1 Ethernet | MAC, VLAN/QinQ tags, IPv4, IPv6, ARP |
| 101 RAW | raw IPv4/IPv6 |
| 108 LOOP | network-order loopback family dispatch |
| 113 Linux SLL | protocol/address metadata + L3 dispatch |
| 228 IPv4 | direct IPv4 |
| 229 IPv6 | direct IPv6 |
| 276 Linux SLL2 | interface/protocol/address metadata + L3 dispatch |

## Network/transport

- IPv4 + fragmentation metadata
- IPv6 + common extension headers and fragmentation metadata
- TCP flags/sequence/ack + bounded directional reconstruction
- UDP
- ICMP/ICMPv6 basic type/code + echo identifiers
- ARP

## Application metadata

- DNS over UDP and single-message DNS-over-TCP segments/streams
- HTTP/1.x request/response headers with sensitive-value redaction
- TLS plaintext handshakes: ClientHello, ServerHello, certificate records where visible
- DHCP/BOOTP common options
- NTP basic header metadata

## Not implemented

- IP fragment reassembly
- HTTP/2 or HTTP/3 content decoding
- QUIC decryption/inspection
- TLS payload decryption
- full TCP state-machine semantics
- every PCAP DLT or every protocol field
