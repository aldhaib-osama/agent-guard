# agentguard: runtime tool-call guard for LLM agents, with a red-team harness

A policy enforcement layer between an agent and its tools, plus a simulated environment and attack suite that measures what the guard stops and what legitimate work it blocks. Python 3.9+, standard library only. No network, no API keys, no cost.

## Guard layers (each independent)
1. Tool allowlist.
2. Argument validation by parsing: path normalisation against a sandbox root, URL parsing with host allowlist (exact or suffix), single-address e-mail parsing (rejects multi-recipient and lookalike domains).
3. Heuristic secret-leak detection in outbound arguments: raw, URL-encoded, hex, selected base64 alignments, reversed.
4. Private-content overlap check, then session taint tracking: when private data and untrusted content share the context, calls to untrusted destinations are denied even if no known secret appears (this catches chunked exfiltration the leak detector cannot see).
5. Undecidable calls require approval through a callback (default: deny).
Every decision is appended to an audit log.

## What the depth pass added
- **Policy as a file** (`policies/default.json`, `policyfile.py`): strict JSON validation (unknown keys, bad hosts, bad channels, missing tool args all raise `PolicyError`). `--validate-policy FILE` checks a file. `--benchmark --policy FILE` actually uses it in the simulated benchmark, with the fictional demo canary supplied by trusted code.
- **Private-content overlap heuristic**: text returned by private-data tools is remembered as 12-character shingles. If a later outbound argument to an untrusted destination overlaps with it, the call is denied by the `provenance` layer and is not approvable, even with an approver. This is session-held content fingerprinting, not true per-value provenance or tracked information flow. It is narrower than the session-wide trifecta block, which still exists.
- **Audit redaction**: the audit log records the decision and no actual destination host/domain, body, path or query string. Hostnames can themselves contain private text, so only a destination-omitted category is retained.
- **Model adapter loop** (`agent.py`): `ModelAdapter` protocol, a scripted `MockModel` with `obey_rate` and `seed`, and `run_adapter`.
- **Generated attack corpus** (`corpus.py`): 78 attacks built from encodings x channels x locations, plus 10 benign tasks.
- **Benchmark** (`benchmark.py`, CLI `--benchmark`): splits, first blocking layer, failures, and layer ablation (`--disable trifecta leak-detector provenance`).

## Evaluation (scripted model, simulated world)
```
export PYTHONPATH=src
python3 -m agentguard.cli --benchmark                 # obey_rate 1.0
python3 -m agentguard.cli --benchmark --approve       # approver says yes to everything
python3 -m agentguard.cli --benchmark --approve --disable trifecta
python3 -m agentguard.cli --benchmark --obey-rate 0.5 --seed 3 --json
python3 -m agentguard.cli                             # original 14 hand-written scenarios
python3 -m agentguard.cli --audit A7
python3 -m unittest discover -s tests -v
```
Results from the default run (obey_rate 1.0, no approver), Python 3.10:

| split | meaning | attacks | succeed unguarded | succeed guarded |
|---|---|---|---|---|
| dev | kinds the guard was designed against | 30 | 30 | 0 |
| heldout | same-author labelled variants, not independently frozen | 42 | 42 | 0 |
| residual | known unaddressed flows (trusted-host logs) | 6 | 6 | 2 |

- Over-blocking: only 7 of 10 benign tasks complete. The 3 blocked ones are a query string on an untrusted host, an email to an external partner, and a write outside `out/`. These need human approval by design. With an approver that approves all, 10 of 10 complete and no dev/heldout attack succeeds; 2 of 6 residual attacks still succeed.
- Ablation with an approver that approves everything: switching off the trifecta rule lets 6 dev and 38 heldout attacks through. Switching off trifecta and the leak detector lets 24 dev and all 42 heldout through. So the layers are not redundant, and a careless approver defeats the guard.
- The heldout name is a corpus label, not an independently frozen evaluation. The author of both is the same, and review repairs changed the guard after that split existed. It cannot establish generalisation.
- 0 guarded successes on dev and heldout is a result on this synthetic corpus, not a security claim.

## Limits (read before quoting any number)
- The model is scripted. `MockModel` follows or ignores an injected directive with a set probability. No real LLM was called, so nothing here measures any model's robustness. To evaluate a real model, someone must write an adapter for `ModelAdapter`; that is not done.
- Trifecta is session-wide, and the so-called provenance layer is shingle overlap (12 characters). A paraphrase, summary, translation or re-encoding of private text is not tracked automatically.
- Taint depends on the adapter labelling tool results correctly. `reads_private` is metadata.
- A harmful but allowed email to a trusted domain passes. Trusted domains are a broad demo assumption.
- No SSRF, DNS-rebinding or redirect enforcement. No real HTTP adapter exists.
- Residual flows (trusted-host logs) succeed in 2 of 6 cases, and are reported as such.

## Status and attribution
Educational prototype, not production-ready. Built with AI assistance, then reviewed by an independent AI reviewer. Dahab has not yet run or reviewed this project. Tests were run only on Python 3.10 (47 tests); the Python 3.9 and 3.12 CI configuration was not run. It is a portfolio prototype, not a production tool and not evidence of anyone's proficiency. Runtime has no third-party dependencies; setuptools is needed only for package installation.

## Adapter and trust boundary
- This is an in-memory simulation. POSIX string checks are not a filesystem sandbox: real adapters must handle symlinks, races, platform path rules and process isolation.
- Parsed host allowlists do not prevent SSRF, DNS rebinding, redirects, proxy behavior or compromised trusted hosts. No real HTTP adapter is implemented. Any adapter must independently enforce destination policy on every connection and redirect.
- Trusted domains are a deliberately broad demo assumption, not recipient-level approval. A harmful but policy-shaped action to a trusted recipient can pass; a regression explicitly documents this residual risk.
- Taint depends on the adapter correctly labelling results. It is not automatic information-flow tracking and does not stop an agent bypassing the wrapper. `reads_private` is metadata only.
- Schemas cover only the five demo tools. Unknown schemas/channels and malformed arguments fail closed. New adapters require explicit schema code and security review.
- Audit stores no argument bodies because they can contain secrets. It records decisions, not replayable calls. Approval callbacks may see raw arguments and must be trusted.
- Secret matching is heuristic and has false positives and bypasses. Short secrets are matched literally, not promised across all encodings. No detection percentage generalizes beyond the scripted scenarios.

## Expanded-feature review
See REVIEW_NOTES.md and TEST_RESULTS.txt. All 47 tests passed on Python 3.10.12, including twelve new independent review tests. Python 3.9/3.12 CI is configured, not executed. Package installation and installed benchmark were checked without source-path configuration.

- Policy files cannot disable layers, relabel the five known adapters' channels or add extra outbound recipient fields. Custom adapter names still need trusted adapter implementations; policy validation does not supply an adapter or verify its effects.
- Approval callbacks receive a detached copy of the validated string arguments. They cannot mutate the actual proposal through that copy. Only a literal boolean True approves; exceptions deny. This is a synchronous callback, not a secure human-confirmation UI or a guarantee against concurrent mutations in real systems.
- A DENY from content-overlap cannot be approved under the default layers. Trusted code can deliberately disable that layer for ablation; do not deploy benchmark ablation settings as a safety policy.
- Audit omits destinations as well as arguments. Actual domains can carry secrets too. Tool names and decisions remain; audit is not replayable and does not retain a raw proposal. Session fingerprints and adapter transcripts still hold sensitive derived/raw information in memory and need their own handling in a real integration.
- Generated attack success now requires every expected payload-bearing simulated side effect, not merely one contact to a destination. This checks the fake world's effects, not real DNS/HTTP delivery or whether an attacker can reconstruct/decode the payload. Corpus variants are correlated, not independent trials.
- Mock obey_rate is finite in [0,1] and only controls whether this scripted directive format is followed. A value of 0 is not evidence of a robust model. No real LLM adapter or real-tool sandbox is implemented.

```sh
python3 -m agentguard.cli --benchmark --policy policies/default.json --json
```

Optional installation: create a virtual environment, update pip/setuptools/wheel, then `python -m pip install .`. The installed `agentguard --benchmark --json` works without a checkout. Policy validation/use requires the path to a policy file you supply. All supplied examples use fake data only.

The default policy is also packaged in `src/agentguard/data/default.json` so installed demos work. If editing the default policy, update both copies; a regression checks they match.
