# SecureBank Network Defense Simulator
**Network & Security - Unit 4** | Streamlit Cloud simulator + optional local dummy banking lab

> Analyse the impact of ARP spoofing, MITM and DDoS-style service disruption on communication and availability; demonstrate the CIA Triad, firewall, IDS/IPS, network segmentation and defence-in-depth; compare the system before and after security mechanisms.

**Safety first.** This is a *teaching prototype with fictional data*. The Cloud app contains **no** packet crafting, sockets, ARP tooling, credential interception or traffic generation: attack mechanics are plain Python state changes over synthetic data. The local lab only talks to its own dummy service on loopback, with hard request/time caps. Run demonstrations only in an isolated, instructor-approved lab. Nothing here is a secure banking product.

| Badge | Meaning |
|---|---|
| `SIMULATED` | Produced by scenario code in `src/` (deterministic for a fixed seed). Used by the whole Cloud app. |
| `LOCAL MEASURED` | Real timings/counts from the local dummy service via `local_lab/test_harness.py`. |

---
## 1. Project tree
```
app.py                      Streamlit UI (6 tabs)
requirements.txt            streamlit, pandas
requirements-dev.txt        + pytest
pytest.ini
.streamlit/config.toml
.gitignore
README.md
src/
  schemas.py                constants, ControlConfig, Event, RunResult, CSV schema
  controls.py               Firewall, Segmentation, RateLimiter, IDS, IPS, ArpGuard, AccessControl, HMAC, validation
  simulator.py              ARP spoofing / MITM / DDoS simulations + layer ablation + safety caps
  cia_tests.py              Confidentiality / Integrity / Availability checks
  metrics.py                percentiles, request metrics, comparison, CSV export
data/
  dummy_accounts.json       3 fictional accounts + placeholder tokens
  demo_hmac_key.txt         demonstration HMAC key (NOT a secret)
local_lab/
  banking_service.py        dummy service: /health /balance /transfer-simulated /_monitor (loopback only)
  test_harness.py           bounded checks + load test + CSV (LOCAL MEASURED)
  README_LOCAL_LAB.md
  docker/                   OPTIONAL Dockerfile + compose (internal network)
tests/
  test_controls.py  test_simulator.py  test_cia_tests.py  test_local_lab.py
```

## 2. Architecture
```
                    +------------------ Streamlit Community Cloud ------------------+
 Browser  <------>  |  app.py (UI)                                                  |
                    |    |                                                          |
                    |    v                                                          |
                    |  simulator.py --uses--> controls.py (rule engines)            |
                    |    |  \--> cia_tests.py       |                               |
                    |    v                          v                               |
                    |  metrics.py -> CSV     data/dummy_accounts.json               |
                    |  [ everything labelled SIMULATED, no network I/O ]            |
                    +---------------------------------------------------------------+

   YOUR MACHINE (optional, never started by the Cloud app)
   +--------------------------------------------------------------------------+
   | test_harness.py --HTTP, loopback only, capped--> banking_service.py      |
   |   (legit client + burst client)                   access control, input  |
   |                                                   validation, rate limit,|
   |                                                   IDS, IPS, HMAC, logs   |
   |   writes local_results.csv [LOCAL MEASURED] --> upload in 'Before vs After' tab
   +--------------------------------------------------------------------------+
```
Simulator request pipeline (DDoS): `segmentation -> firewall -> IPS blocklist -> IDS observe -> rate limit -> access control -> service queue`.

## 3. Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v                # or: pytest
streamlit run app.py
```
Local lab (separate terminals, see `local_lab/README_LOCAL_LAB.md`):
```bash
python local_lab/banking_service.py --port 8080
python local_lab/test_harness.py --checks --compare
```

## 4. Deploy on Streamlit Community Cloud (simulator only)
1. Create a **public GitHub repo** and push this folder (`git init && git add . && git commit -m "SecureBank simulator" && git branch -M main && git remote add origin <your-repo-url> && git push -u origin main`).
2. Go to <https://share.streamlit.io>, sign in with GitHub, click **Create app** -> *Deploy a public app from GitHub*.
3. Repository: your repo; Branch: `main`; Main file path: `app.py`.
4. (Optional) *Advanced settings* -> Python 3.11 or 3.12. No secrets are needed - leave the Secrets box empty.
5. Click **Deploy**. The app starts with sample results for all three scenarios already computed.

The Cloud app needs no raw sockets, admin rights or packet capture and never starts `local_lab/`.

<!--METHODOLOGY-->
## 5. Threat model and scope
* **In scope:** a fictional bank with zones `internet`, `user-lan`, `dmz`, `db-zone`; a *simulated* LAN attacker (ARP spoofing -> on-path MITM) and *simulated* distributed bots (flooding).
* **Assets:** fictional balances (confidentiality), transfer messages (integrity), service responsiveness (availability).
* **Out of scope:** real networks, real banks, zero-days, malware, physical attacks, TLS/PKI internals, anything outside the dummy service.

## 6. CIA Triad mapping
| Property | Threat shown | Control(s) | Test (CIA tab) |
|---|---|---|---|
| Confidentiality | MITM reads plaintext; unauthorised balance lookup | Access control, (simulated) encryption, ARP protection | Owner allowed; no-token, bad-token, cross-account denied |
| Integrity | MITM alters amount in transit | HMAC-SHA256, IDS/IPS on failures | Original passes; modified amount/memo/forged MAC fail |
| Availability | DDoS-style burst starves legitimate users | Rate limiting, IDS+IPS, firewall, segmentation | Normal vs burst vs burst+rate limit |

## 7. Mechanisms: simulated or actually implemented?
| Mechanism | Cloud simulator | Local dummy service |
|---|---|---|
| Firewall | **Simulated** application-layer first-match, default-deny rule table (not a network firewall) | Application-layer routing/validation only. Host firewall: optional manual step, never automatic |
| IDS | **Simulated** explicit signatures (`RATE_EXCEEDED`, `REPEATED_FAILURES`, `ARP_MAPPING_CONFLICT`, `INTEGRITY_FAILURE`) | **Implemented** same signatures on live request events (rate/failures). Not a production IDS |
| IPS | **Simulated** block of source/frame/message after a signature fires | **Implemented**: temporary block (HTTP 403) of the client id |
| Segmentation | **Simulated** zone policy enforced in code | Optional Docker `internal: true` network (not tested in this build) |
| ARP protection | **Simulated** trusted-binding check (DAI-like) | n/a (no ARP in local lab) |
| Rate limiting | Simulated fixed window per source per second | **Implemented** fixed window per `X-Client-Id` (HTTP 429) |
| Access control | Simulated pipeline stage over fictional tokens | **Implemented** token auth + per-account authorisation |
| Integrity | **Implemented** real HMAC-SHA256 on dummy messages | **Implemented** same HMAC on `/transfer-simulated` |
| Encryption | **Simulated flag only** | Not implemented (use TLS in real systems) |
| Defence-in-depth | Layer-ablation table: each control alone vs all | Combined controls compared by harness |

## 8. Before/after metric definitions
* **legit_success_rate_pct** - served legitimate requests / all legitimate requests.
* **request_success_rate_pct** - served requests / all requests (attack included).
* **avg_latency_ms_legit, p95_latency_ms_legit** - over *served* legitimate requests (linear-interpolation percentile). Simulated ms in cloud mode; real ms in local mode.
* **availability_pct** - share of simulated seconds in which >= 90 % of legitimate requests were served.
* **requests_rejected_by_controls** - denied/blocked/rate-limited/auth-rejected; **requests_dropped_or_timed_out** - overload drops and timeouts.
* **detection_count** - IDS alerts. **block_count** - requests/frames/messages blocked by the IPS.
* **caches_poisoned, diversion_rate_pct** - ARP: hosts whose gateway entry maps to the attacker; share of messages sent to the attacker.
* **messages_read_by_attacker, tampered_accepted, tampered_detected, integrity_check_outcome** - MITM.
* **CSV** columns: `run_id, mode, source, scenario, phase, metric, value, seed, controls_active` (long format, `mode` = `SIMULATED` or `LOCAL MEASURED`).

No number is a hard-coded constant: all are computed from run records/events. With seed 42 the default DDoS run is reproducible (e.g. legitimate success 67.5 % without controls vs 100 % with all layers in this build's model).

## 9. Simulation assumptions (read before the viva)
* 1 tick = 1 simulated second; the simulated service handles 60 req/tick, queues 120, abandons requests after 3 ticks.
* Rejected requests cost no service capacity (a simplification; real filtering costs CPU/bandwidth).
* Hosts accept unsolicited ARP replies in the baseline. Without segmentation the LAN is one flat broadcast domain.
* The MITM attacker is on-path unless ARP protection is on; encryption is a flag; the HMAC key is a repository demo key.
* Caps: <= 60 ticks, <= 20,000 simulated requests, <= 500 messages per run; local harness <= 500 requests, 30 s, 8 threads, loopback only, stop with Ctrl+C or a `local_lab/STOP` file.

## 10. Limitations
* Not a production banking service, not a real IDS/IPS/firewall, no live attacks are performed by Cloud mode, and Cloud results say nothing about the hosting network.
* Per-client rate limits are weak against distributed sources; client identity in the local lab is a self-asserted header.
* Shared demo key, no replay protection, no TLS, no persistence, no real key management.
* Local latencies depend on your machine; the artificial `--work-ms` delay and 2-worker capacity exist only to make queueing visible.

## 11. Local lab boundaries
Loopback only; fictional data; no automatic firewall changes; bursts capped and stoppable; the harness refuses non-local targets. See `local_lab/README_LOCAL_LAB.md`.

## 12. Viva prompts
* **ARP:** Why can any host poison a cache? What do static entries / DAI change? Why does IDS alone not stop poisoning?
* **MITM:** What does the attacker gain from plaintext? Why doesn't HMAC give confidentiality? What does a shared demo key fail to prove? What is replay?
* **DDoS:** Why does queueing raise latency before drops start? Why is per-source rate limiting weak against many sources? What can't in-app controls stop?
* **CIA:** Which scenario hits which property? Can one control cover all three?
* **Firewall:** Application-layer rules vs network firewall? What does default-deny buy you?
* **IDS/IPS:** Detect vs prevent? Cost of false positives when the IPS blocks? Why are fixed thresholds fragile?
* **Segmentation:** Why does it reduce blast radius but not protect hosts *inside* a zone? Why are drawn boxes not segmentation?
* **Defence-in-depth:** Use the layer table: which layer stops what, and what remains when one layer fails?
