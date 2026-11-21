"""Benchmark runner: generated corpus, split reporting, optional partial-obedience model, approver on/off."""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Dict, List

from .agent import MockModel, run_adapter
from .corpus import all_scenarios
from .guard import ALLOW, Guard, Session
from .world import World, default_policy


def run_scenario(s, guarded: bool, obey_rate: float = 1.0, seed: int = 0, approve: bool = False, disable=(), policy=None) -> Dict[str, Any]:
    w = World()
    s.setup(w)
    sess = Session()
    guard = Guard(policy if policy is not None else default_policy(), approver=(lambda *a: True) if approve else None, disabled_layers=set(disable))
    blocked: List[str] = []

    def execute(tool, args):
        if guarded:
            d = guard.check(tool, args, sess)
            if d.verdict != ALLOW:
                blocked.append(d.layer)
                return f"BLOCKED: {d.reason}", False, False
        fn = getattr(w, tool, None)
        if fn is None:
            return "unknown tool", False, False
        res = fn(**args)
        if guarded:
            guard.observe_result(tool, res.untrusted, res.private, sess, res.text)
        return res.text, True, res.untrusted

    run_adapter(MockModel(s.plan, obey_rate, seed), execute)
    return {"success": s.success(w), "blocked_layers": blocked, "audit": sess.audit}


def evaluate(obey_rate: float = 1.0, seed: int = 0, approve: bool = False, disable=(), policy=None) -> Dict[str, Any]:
    groups: Dict[str, Dict[str, List[Any]]] = defaultdict(lambda: {"unguarded": [], "guarded": []})
    layers: Dict[str, int] = defaultdict(int)
    failures: List[str] = []
    for s, meta in all_scenarios():
        u = run_scenario(s, False, obey_rate, seed, approve, policy=policy)
        g = run_scenario(s, True, obey_rate, seed, approve, disable, policy=policy)
        groups[meta.split]["unguarded"].append(u["success"])
        groups[meta.split]["guarded"].append(g["success"])
        for layer in g["blocked_layers"][:1]:
            layers[layer] += 1
        if meta.split in ("dev", "heldout") and g["success"]:
            failures.append(f"{s.id} {s.desc}")
        if meta.split == "benign" and not g["success"]:
            failures.append(f"over-block: {s.id} {s.desc}")
    out: Dict[str, Any] = {"disabled_layers": sorted(disable), "obey_rate": obey_rate, "approver_approves": approve, "splits": {}, "first_block_layer": dict(layers), "failures": failures}
    for split, d in groups.items():
        n = len(d["guarded"])
        out["splits"][split] = {"n": n, "unguarded_success": sum(d["unguarded"]), "guarded_success": sum(d["guarded"]),
                                "unguarded_rate": round(sum(d["unguarded"]) / n, 3), "guarded_rate": round(sum(d["guarded"]) / n, 3)}
    out["caveat"] = ("Scripted/mock model. dev = attacks the guard was designed against; heldout = same-author labelled variants, not an independently frozen split; "
                     "residual = known unaddressed flows. For benign, 'success' means the task completed.")
    return out
