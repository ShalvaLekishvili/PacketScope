# Investigation Workflow

## 1. Establish evidence identity

Record the capture SHA-256/evidence ID shown in Overview or the HTML report. This lets exported analysis stay tied to the original file.

## 2. Triage priority hosts

Start with host risk scores, bytes, destinations, protocols and attributed finding IDs. A high host score is a triage aid, not a verdict.

## 3. Review findings

Open a finding and validate:

- rule/confidence
- evidence endpoints/domains
- packet IDs
- temporal shape/counts
- recommendation
- ATT&CK context where present

## 4. Pivot

Use Network Graph, Flows and Protocol Intel to determine whether a lead is isolated or part of broader activity. DNS/HTTP/TLS transaction views are especially useful for timing and directionality.

## 5. Record disposition

For web-upload sessions save a status, verdict, note and tags. This state is local to the investigation session.

## 6. Export exact evidence

Use **Export related packets** from a finding. PacketScope re-reads the source capture and creates a PCAPNG containing the referenced original frames. Continue detailed byte-level review in Wireshark/tcpdump as needed.

## 7. Report and close

Export HTML/JSON. Explicitly close the session when practical; otherwise the configured TTL cleanup removes expired local sessions.
