from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .agent import ScriptedAgent
from .guard import ALLOW, Guard, Session
from .scenarios import Scenario, build
from .world import World, default_policy


@dataclass
class Outcome:
    id: str
    kind: str
    desc: str
    success: bool
    blocked_by: List[str]
    audit: List[Dict[str, Any]]


def run_one(s: Scenario, guarded: bool) -> Outcome:
    w = World()
    s.setup(w)
    sess = Session()
    guard = Guard(default_policy())
    blocked: List[str] = []

    def execute(tool: str, args: Dict[str, Any]):
        if guarded:
            d = guard.check(tool, args, sess)
            if d.verdict != ALLOW:
                blocked.append(f"{tool}: [{d.layer}] {d.reason}")
                return f"BLOCKED: {d.reason}", False
        fn = getattr(w, tool, None)
        if fn is None:
            return "unknown tool", False
        res = fn(**args)
        if guarded:
            guard.observe_result(tool, res.untrusted, res.private, sess, res.text)
        return res.text, True

    ScriptedAgent(s.plan, obeys_injection=True).run(execute)
    return Outcome(s.id, s.kind, s.desc, s.success(w), blocked, sess.audit)


def evaluate() -> Dict[str, Any]:
    rows = {"unguarded": [], "guarded": []}
    for s in build():
        rows["unguarded"].append(run_one(s, False))
        rows["guarded"].append(run_one(s, True))
    def metrics(outs):
        atk = [o for o in outs if o.kind == "attack"]
        ben = [o for o in outs if o.kind == "benign"]
        return {"attack_success_rate": sum(o.success for o in atk) / len(atk),
                "benign_task_completion": sum(o.success for o in ben) / len(ben),
                "attacks": len(atk), "benign": len(ben)}
    return {"metrics": {k: metrics(v) for k, v in rows.items()}, "rows": rows}
