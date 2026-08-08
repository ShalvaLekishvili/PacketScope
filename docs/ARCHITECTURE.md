# PacketScope 2.0 Architecture

## Design goals

PacketScope is local-first, deterministic, bounded and evidence-oriented. The core analysis engine does not depend on the web UI and the same result model is used by CLI, API, reports and tests.

## Pipeline

1. **Capture reader** validates PCAP/PCAPNG block/header bounds and emits `PacketRecord` objects.
2. **Protocol parser** decodes supported link/network/transport/application metadata without executing capture content.
3. **Normalizer** adds 1-based packet IDs and builds bounded event collections.
4. **Flow engine** creates directional flows and canonical bidirectional conversations.
5. **TCP reconstruction** sorts sequence-numbered payload segments, handles overlap/retransmission bytes and stops at missing gaps.
6. **Correlation** pairs DNS queries/responses, HTTP requests/responses and TLS handshake directions where metadata is available.
7. **Host profiler** attributes bytes, protocols, destinations, domains/SNI and findings to endpoints.
8. **Graph builder** emits host traffic plus DNS/TLS-name pivots for the frontend.
9. **Detection engine** evaluates metadata heuristics, applies allowlists/suppressions and computes a confidence-weighted risk score.
10. **Workspace** stores local capture/result/annotations under a random session ID and creates PCAPNG evidence slices from finding packet IDs.

## Bounded processing

Defaults in `AnalysisLimits` constrain packets, normalized events, protocol records, flows, streams, stream bytes and evidence packet-ID lists. Web uploads are separately size-limited.

The intent is graceful degradation on large/untrusted captures rather than unbounded in-memory retention.

## Evidence model

Every parsed normalized event receives a 1-based `packet_id`. Detections retain bounded packet-ID references inside `finding.evidence.packet_ids`. Slicing re-reads the original capture and writes only those records to a new PCAPNG file, preserving timestamps, original lengths and link types.

The capture SHA-256 is calculated before result delivery and included as `capture.sha256` with a short `evidence_id`.

## TCP reconstruction semantics

PacketScope reconstruction is directional and intentionally conservative:

- sequence-sort segments
- accept new contiguous bytes
- account for retransmitted/overlapping bytes
- stop at the first positive sequence gap
- never insert placeholder data for missing bytes
- cap reconstructed bytes per stream

This provides enough context for split HTTP/TLS headers without claiming full TCP-stack equivalence.

## Packaging

Frontend assets and the synthetic demo are package data under `packetscope/web` and `packetscope/sample_data`. An installed wheel therefore retains the web workbench instead of depending on repository-relative files.
