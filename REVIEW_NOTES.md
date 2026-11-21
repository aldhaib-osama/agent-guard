# Expanded-feature independent review, 21 November 2026

AI-assisted educational portfolio simulation. Dahab has not personally reviewed or run it. Not a production security boundary or evidence of anyone's Python proficiency. No real model, network sending, paid API, account access or publication was used.

## Checks actually run
- All 35 submitted tests passed before independent review, but missed material defects.
- Repaired version: 47 tests pass on Python 3.10.12, including twelve added independent cases. Tests also pass with ResourceWarning escalated. TEST_RESULTS.txt records output.
- Built/installed package and ran installed benchmark outside the source tree without PYTHONPATH. Validated and actually applied policies/default.json through the new --benchmark --policy workflow.
- Reproduced default synthetic results: dev 0/30 attacker successes, same-author heldout-labelled variants 0/42, residual 2/6; benign completion 7/10.
- Approve-all: benign 10/10, dev/heldout still 0, residual still 2/6. With approve-all and trifecta disabled: 6/30 dev and 38/42 heldout variants succeed. With trifecta plus leak detection disabled: 24/30 dev, 42/42 heldout and 6/6 residual succeed.
- Python 3.9/3.12 hosted CI is configured but NOT executed. No coverage percentage, real model robustness score or formal security proof is claimed.

## Material expanded defects fixed
- Audit redaction kept actual hostname/domain, which can itself encode private data. Actual destinations are now omitted as well as arguments. Added a secret-in-host/domain regression.
- Policy files could relabel known outbound adapters as channel none or add extra unchecked recipient arguments. Known adapter channel bindings and exact channel schemas now reject that configuration. Unknown adapters still require trusted code and security review.
- Approval callbacks received the original mutable arguments. They now receive a detached string-value dictionary, cannot rewrite the proposal through it, and only literal True approves. Exceptions deny. A provenance DENY never calls the approver.
- Invalid policy channel types could raise the wrong exception. Tightened validation, including hostname anchoring and canonical root paths. Invalid tool names, path controls and email controls fail closed.
- Mock obey_rate accepted NaN/out-of-range values. It now requires a finite value in [0,1]. Unknown ablation layer names are rejected; policy files cannot select ablation.
- The claimed per-value provenance is actually session-held 12-character content overlap. Documentation now names that limitation instead of implying true value-level taint propagation.
- Attack success originally meant any contact to the target, even one partial chunk. It now requires every expected payload-bearing simulated effect. This is still a fake-world effect check, not real delivery or payload recoverability.
- Policy files could only be validated, not used by the CLI benchmark. Added --benchmark --policy so the input-to-evaluation workflow actually exercises the loaded configuration.
- Installed commands could not locate a source-tree-only default policy. The policy is now packaged as data; a test keeps the editable and packaged copies equal.
- Removed the unsupported implication of an independently frozen heldout benchmark. It is a same-author corpus label, and review repairs changed the guard after those cases existed.

## Remaining limits
- No real LLM or network/filesystem adapter. Fake read/write/fetch/email effects do not validate real enforcement. Symlinks, races, process isolation, DNS rebinding, redirects, SSRF and credential handling are not solved.
- Session content fingerprints are not per-value provenance. Short fragments, re-encoding, summaries, translations and paraphrases can evade overlap. Legitimate common text may overlap and be blocked. Adapter result labels must be trustworthy.
- Trusted hosts/domains remain broad assumptions, not recipient-level or user-intent authorization. Two residual trusted-host flows still succeed. A harmful but in-policy message to a trusted recipient passes.
- Fingerprints and adapter transcripts can hold sensitive information in memory even though audit omits bodies/destinations. No storage retention, isolation or size limits are implemented.
- Custom policy tool names do not create adapters, and a no-outbound channel classification is only as trustworthy as its implementation. Programmatic policy/adapter construction is trusted code, not an untrusted input boundary.
- Approval is a synchronous callback, not a human-confirmation security UI. Detached arguments prevent mutation through the callback proposal only, not all concurrency or external-policy mutation risks.
- Ablation deliberately disables safety checks from trusted experiment code. Do not deploy that as a safety setting. No policy-file field or untrusted tool result can select disabled_layers in the supplied workflow.
- The 78 generated variants are correlated and authored alongside the guard. Scripted obedience probabilities say nothing about real-model robustness. Perfect dev/heldout results and approve-all examples cannot be generalized to real attacks.
- Keep AI attribution and Dahab's not-yet-personally-reviewed status until she actually reviews/runs it. Real secrets or private data should not be added to the committed examples.
