from __future__ import annotations
import argparse
import json
import sys

from .harness import evaluate


def _main(argv=None):
    ap = argparse.ArgumentParser(prog="agentguard")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--audit", metavar="ID", help="print the guard audit log for one scenario id (guarded run)")
    ap.add_argument("--benchmark", action="store_true", help="run the generated corpus with dev/heldout/residual/benign splits")
    ap.add_argument("--obey-rate", type=float, default=1.0, help="probability the mock model follows an injected directive")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--approve", action="store_true", help="approver approves every needs-approval call (shows over-block vs risk)")
    ap.add_argument("--disable", nargs="*", default=[], choices=["trifecta", "leak-detector", "provenance"], help="ablation: switch layers off")
    ap.add_argument("--policy", metavar="FILE", help="use a validated policy in the simulated benchmark only")
    ap.add_argument("--validate-policy", metavar="FILE", help="validate a policy JSON file and exit")
    a = ap.parse_args(argv)
    if a.validate_policy:
        from .policyfile import load_policy, PolicyError
        try:
            p = load_policy(a.validate_policy)
        except (PolicyError, OSError) as e:
            print(f"invalid: {e}", file=sys.stderr)
            return 1
        print(f"ok: {len(p.tools)} tool(s): {', '.join(p.tools)}")
        return 0
    if a.benchmark:
        from .benchmark import evaluate as bench
        policy = None
        if a.policy:
            from .policyfile import load_policy
            from .world import SECRET
            policy = load_policy(a.policy, secrets=[SECRET])  # fictional canary, never a real credential
        rep = bench(a.obey_rate, a.seed, a.approve, tuple(a.disable), policy=policy)
        if a.json:
            print(json.dumps(rep, indent=2))
        else:
            print(f"disabled layers: {rep['disabled_layers'] or 'none'} | obey_rate={rep['obey_rate']} | approver approves: {rep['approver_approves']}")
            print(f"{'split':9} {'n':>3} {'unguarded':>10} {'guarded':>8}")
            for k in ("dev", "heldout", "residual", "benign"):
                d = rep["splits"][k]
                print(f"{k:9} {d['n']:>3} {d['unguarded_success']:>10} {d['guarded_success']:>8}   ({'task completed' if k == 'benign' else 'attacks that succeeded'})")
            print("first blocking layer:", rep["first_block_layer"])
            for f in rep["failures"]:
                print("  -", f)
            print(rep["caveat"])
        return 0
    if a.policy:
        raise ValueError("--policy is supported with --benchmark only")
    r = evaluate()
    if a.audit:
        for o in r["rows"]["guarded"]:
            if o.id == a.audit:
                for ent in o.audit:
                    print(json.dumps(ent))
        return 0
    if a.json:
        print(json.dumps(r["metrics"], indent=2))
        return 0
    print(f"{'id':3} {'kind':7} {'unguarded':10} {'guarded':8}  description")
    for u, g in zip(r["rows"]["unguarded"], r["rows"]["guarded"]):
        lab = (lambda o: ("ATTACK OK" if o.success else "stopped") if o.kind == "attack" else ("done" if o.success else "FAILED"))
        print(f"{u.id:3} {u.kind:7} {lab(u):10} {lab(g):8}  {u.desc}")
        for b in g.blocked_by[:1]:
            print(f"{'':23}-> {b}")
    m = r["metrics"]
    for k in ("unguarded", "guarded"):
        print(f"{k:10} attack success {m[k]['attack_success_rate']:.0%} | benign completion {m[k]['benign_task_completion']:.0%}")
    return 0


def main(argv=None):
    try:
        return _main(argv)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
