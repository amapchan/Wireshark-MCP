# Playbooks

Use these mode-specific playbooks after the initial overview in `SKILL.md`.

## Contents

- [Triage](#triage)
- [Security](#security)
- [Incident Response](#incident-response)
- [Troubleshoot](#troubleshoot)

## Triage

Goal: explain what the capture mostly contains, identify the main communicators, and point to the three best next leads.

Recommended flow:

1. `wireshark_open_file`
2. `wireshark_quick_analysis`
3. `wireshark_stats_protocol_hierarchy`
4. `wireshark_stats_endpoints`
5. `wireshark_stats_conversations`
6. `wireshark_stats_io_graph` if timing matters
7. Follow the most relevant streams with `wireshark_follow_stream`

Interpretation notes:

- Use endpoints to answer "who is present?"
- Use conversations to answer "who is actually exchanging meaningful traffic?"
- Do not sum protocol hierarchy percentages across rows as if they were exclusive buckets.

Deliver:

- capture summary
- top protocols and top talkers
- any obvious anomalies
- the three most valuable filters, streams, or hosts to inspect next

## Security

Goal: determine whether the capture shows suspicious behavior and explain why.

Recommended flow:

1. Start with the triage playbook.
2. Run `wireshark_quick_analysis` for a broad first pass.
3. Verify specific signals with:
   - `wireshark_extract_credentials`
   - `wireshark_detect_port_scan`
   - `wireshark_detect_dns_tunnel`
   - `wireshark_detect_beaconing`
   - `wireshark_detect_exfiltration`
4. If HTTP, DNS, or TLS matter, extract evidence with:
   - `wireshark_extract_http_requests`
   - `wireshark_extract_dns_queries`
   - `wireshark_analyze_protocol(protocol="tls_handshakes")`
5. Follow suspicious conversations with `wireshark_follow_stream`.
6. Use `wireshark_get_packet_details` or `wireshark_get_packet_context` to anchor claims in exact frames.

Interpretation notes:

- Treat `wireshark_stats_expert_info` as a shortlist of leads, not proof of compromise.
- When DNS or TLS looks odd, compare the behavior against the counterexamples in `evidence-rubric.md` before escalating severity.

Deliver:

- risk summary
- top suspicious behaviors
- evidence for each finding
- what is confirmed versus what is only likely
- next validation steps

## Incident Response

Goal: reconstruct what happened, when it happened, and which systems were involved.

Recommended flow:

1. Start with the triage playbook.
2. Use `wireshark_get_file_info` to understand duration and capture boundaries.
3. Use `wireshark_stats_endpoints` and `wireshark_stats_conversations` to map actors.
4. Use security-focused tools to identify IOCs and suspicious traffic.
5. Follow the streams that matter most for:
   - initial contact
   - credential use
   - lateral movement
   - download or upload behavior
6. When time ordering matters, anchor events with frame numbers and timestamps from `wireshark_get_packet_list` or `wireshark_get_packet_details`.

Interpretation notes:

- Capture start and end times are not the same as incident start and end times.
- Use conversations plus timestamps to separate repeated background traffic from incident-driving exchanges.

Deliver:

- incident timeline
- affected hosts and services
- IOC list
- likely attack narrative
- containment or follow-up recommendations

## Troubleshoot

Goal: explain packet-level causes of slowness, failure, or instability.

Recommended flow:

1. Start with `wireshark_open_file`.
2. Build the baseline with:
   - `wireshark_stats_protocol_hierarchy`
   - `wireshark_stats_endpoints`
   - `wireshark_stats_conversations`
   - `wireshark_stats_io_graph`
3. Use protocol health tools:
   - `wireshark_analyze_tcp_health`
   - `wireshark_stats_expert_info`
   - `wireshark_stats_service_response_time`
4. Follow the problematic stream.
5. Compare client and server behavior before concluding whether the issue is network, application, or remote service behavior.

Interpretation notes:

- Repeated retransmissions, duplicate ACK bursts, zero windows, and resets are stronger together than alone.
- Capture loss and one-sided visibility can mimic network issues. Say so when confidence is reduced.

Deliver:

- symptom summary
- probable bottleneck or failure mode
- exact evidence
- what to test next outside the capture if needed
