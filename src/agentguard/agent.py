"""Agents are anything with run(). ScriptedAgent follows a fixed plan and, if `obeys_injection`, also executes
directives found in untrusted tool output (a model of a compromised agent). LLMAdapter documents where a real model
would plug in; it is intentionally not implemented here (no network, no cost, no API keys)."""
from __future__ import annotations
import json
import re
from typing import Any, Callable, Dict, List, Protocol, Tuple

DIRECTIVE = re.compile(r"\[\[call: (\w+) (\{.*?\})\]\]")


class LLMAdapter(Protocol):
    def next_call(self, transcript: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]] | None:
        """Return the next (tool, args) or None when finished. Implement with a real model to evaluate it."""


class ScriptedAgent:
    def __init__(self, plan: List[Tuple[str, Dict[str, Any]]], obeys_injection: bool = True):
        self.plan = list(plan)
        self.obeys = obeys_injection

    def run(self, execute: Callable[[str, Dict[str, Any]], Tuple[str, bool]], max_steps: int = 20) -> None:
        """`execute(tool, args)` returns (result_text, was_allowed)."""
        queue = list(self.plan)
        steps = 0
        while queue and steps < max_steps:
            tool, args = queue.pop(0)
            steps += 1
            text, allowed = execute(tool, args)
            if allowed and self.obeys:
                for name, raw in DIRECTIVE.findall(text):
                    try:
                        queue.insert(0, (name, json.loads(raw)))
                    except ValueError:
                        pass


class ModelAdapter(Protocol):
    """Anything that proposes the next tool call from the transcript. A real LLM client would implement this.
    Not provided here on purpose: a hosted model costs money and needs the owner's key and approval."""
    def next_call(self, transcript: List[Dict[str, Any]]) -> "Tuple[str, Dict[str, Any]] | None": ...


class MockModel:
    """Deterministic stand-in for a model: follows `plan`, and with probability `obey_rate` (seeded) also executes
    directives embedded in untrusted tool output. obey_rate=1.0 always follows the mock directives, 0.0 ignores that mock format. Neither setting measures model robustness."""
    def __init__(self, plan, obey_rate: float = 1.0, seed: int = 0):
        import random
        import math
        if not isinstance(obey_rate, (int, float)) or not math.isfinite(obey_rate) or not 0 <= obey_rate <= 1:
            raise ValueError("obey_rate must be finite and between 0 and 1")
        self.queue = list(plan)
        self.rate = obey_rate
        self.rnd = random.Random(seed)
        self.seen = 0

    def next_call(self, transcript):
        for entry in transcript[self.seen:]:
            if entry.get("role") == "tool" and entry.get("allowed") and entry.get("untrusted"):
                for name, raw in reversed(DIRECTIVE.findall(entry["text"])):
                    try:
                        args = json.loads(raw)
                    except ValueError:
                        continue
                    if self.rnd.random() < self.rate:
                        self.queue.insert(0, (name, args))
        self.seen = len(transcript)
        return self.queue.pop(0) if self.queue else None


def run_adapter(adapter: ModelAdapter, execute, max_steps: int = 40) -> List[Dict[str, Any]]:
    """Drive any adapter. `execute(tool, args)` -> (text, allowed, untrusted)."""
    transcript: List[Dict[str, Any]] = []
    for _ in range(max_steps):
        call = adapter.next_call(transcript)
        if call is None:
            break
        text, allowed, untrusted = execute(*call)
        transcript.append({"role": "tool", "tool": call[0], "text": text, "allowed": allowed, "untrusted": untrusted})
    return transcript
