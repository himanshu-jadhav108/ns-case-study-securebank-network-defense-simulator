# Local Defensive Lab (optional, dummy service only)

Everything here runs on **your machine only**, against a **fictional** banking service. It is not required for the Cloud app. Use it only in an isolated, instructor-approved lab.

## Safety boundaries
* Service binds to `127.0.0.1`; it refuses other addresses unless `LAB_CONTAINER=1` (Docker lab only).
* Harness refuses any target that is not loopback (or listed in `LAB_ALLOWED_TARGETS` for the Docker lab).
* Hard caps in code: <= 500 requests per phase, <= 30 s, <= 8 threads. Stop with **Ctrl+C** or create the file `local_lab/STOP`.
* No real data, no real payments, no packet capture, no ARP tooling. The scripts never change your firewall.

## Run the service
```bash
python local_lab/banking_service.py --port 8080
# flags: --no-rate-limit --no-ids --no-ips --no-auth --no-integrity --rate-limit 20 --work-ms 25 --capacity 2
```
Endpoints: `GET /health`, `GET /balance?account=ACC-1001` (header `X-Demo-Token: DEMO-TOKEN-ALICE`), `POST /transfer-simulated` (JSON with HMAC `mac`), `GET /_monitor` (stats and recent events). Event log: `local_lab/logs/events.jsonl` (tokens are never logged).

Quick manual check:
```bash
curl -s localhost:8080/health
curl -s -H "X-Demo-Token: DEMO-TOKEN-ALICE" "localhost:8080/balance?account=ACC-1001"
curl -s -o /dev/null -w "%{http_code}\n" "localhost:8080/balance?account=ACC-1001"   # 401, no token
curl -s localhost:8080/_monitor
```

## Run the harness
```bash
python local_lab/test_harness.py --checks      # confidentiality / integrity probes
python local_lab/test_harness.py --compare     # baseline (controls off) vs controls on, fresh in-process services
python local_lab/test_harness.py --load --target http://127.0.0.1:8080 --phase-label with_controls
```
Results go to `local_lab/results/*.csv` with `mode = LOCAL MEASURED`. Upload the CSV in the app's **Before vs After** tab.

To compare phases against a running service: start it with `--no-rate-limit --no-ids --no-ips --no-auth --no-integrity`, run `--load --phase-label baseline`, restart with defaults, run `--load --phase-label with_controls`.

## What you are measuring
A steady legitimate client and a capped burst client (valid token, so only rate limiting/IPS can help). The service has 2 workers and a 25 ms artificial work delay so queueing is visible. Metrics: legitimate success rate, average and p95 latency, burst accepted vs rejected, IDS detections, IPS blocks. Numbers vary by machine - report what you measure.

## Optional: host firewall (manual, instructor-approved only)
This project never changes firewall settings. If your instructor wants a host-level demo, they can show e.g. a rule allowing only `127.0.0.1` to reach port 8080. Do it by hand, understand each command, and remove it afterwards.

## Optional: Docker segmentation (not required, untested in this build)
```bash
docker compose -f local_lab/docker/docker-compose.yml up --build
```
The `lab_internal` network is `internal: true` (no route to the outside); the `client` container runs the capped harness against `bank` only. Only `127.0.0.1:8080` is published to the host.
