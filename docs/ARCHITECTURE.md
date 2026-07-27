# NetMask Sentinel architecture and accuracy guide

## The beginner version

A packet is one small piece of a network conversation. Judging one packet alone is usually unreliable, so NetMask Sentinel combines packets that share source/destination addresses, ports, and protocol into a **flow**. When that flow ends, NetMask Sentinel calculates 39 measurements: duration, packet lengths, timing gaps, TCP flags, packet rate, and window sizes.

The random-forest model receives exactly those 39 numbers. Each tree votes, producing a probability for Benign, Botnet, DDoS, DoS, FTP-Patator, Probe, SSH-Patator, and Web Attack. NetMask Sentinel displays the class with the largest probability. It separately calculates attack probability as the sum of all non-benign probabilities (`1 - P(Benign)`).

Risk levels are policy thresholds, not proof:

- Minimal: below 20%
- Low: 20–39.99%
- Medium: 40–59.99%
- High: 60–79.99%
- Very high: 80% or above

A suspicious result becomes an event. Similar events within the configured window become one incident with an event counter. This reduces repeated notification noise while preserving evidence.

## Main components

- `netmask/sensor.py`: capture workers, bounded queue, flow lifecycle, health state.
- `flow/PacketInfo.py` and `flow/Flow.py`: packet parsing and legacy feature calculations.
- `netmask/features.py`: the single canonical 39-column contract and validation.
- `netmask/detection.py`: thread-safe inference, probabilities, risk policy, model metadata.
- `netmask/incidents.py`: correlation and acknowledgement.
- `netmask/telemetry.py`: counters, errors, uptime, and inference latency.
- `application.py`: authenticated APIs, persistence, Socket.IO delivery, CSRF/session protection.
- `evaluate_model.py`: labeled offline evaluation.
- `replay_pcap.py`: repeatable PCAP replay through the live feature path.

Packet capture and classification use separate worker threads and a bounded queue. A slow model therefore does not directly block packet callbacks; queue depth and dropped flows remain observable in `/api/metrics`.

## What “accurate” means

A smoke test confirms compatibility, feature count, classes, and valid probabilities. It does **not** measure detection accuracy. Professional validation requires an independent labeled dataset captured under realistic conditions.

Focus on:

1. Per-class recall: how many real attacks of each type were found.
2. Per-class precision: how many alerts of that type were correct.
3. Confusion matrix: which classes are confused with each other.
4. False-positive rate on benign traffic.
5. Detection latency and dropped-flow count under load.
6. Calibration: whether an 80% score is correct roughly 80% of the time.

The bundled legacy model metadata explicitly marks probabilities as uncalibrated. Use the evaluation report before changing thresholds. Retrain or calibrate using clean train/validation/test splits grouped by capture session to prevent data leakage.

## Important limits

- Only IPv4 TCP/UDP flows are captured by the default filter.
- Encrypted payload contents are not inspected.
- Process names are best-effort and may require privileges.
- The detector reports behavior resembling its training classes; it does not establish attacker intent.
- In-memory incidents reset when the process restarts; runtime CSV evidence persists locally.
- Firebase absence disables cloud login/history but not local guest detection in development.

Only replay PCAPs and generate traffic on systems you own or are authorized to test.