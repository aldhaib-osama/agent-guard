"""Policy enforcement point that sits between an agent and its tools.

Design (defence in depth, each layer independent):
 1. Tool allowlist: unknown tools are denied.
 2. Argument validation: paths must stay inside the sandbox (after normalisation), URLs and e-mail
    addresses are parsed (not substring-matched) and compared to trusted destinations.
 3. Secret-leak detection in outbound arguments: raw, URL-encoded, hex, selected base64 alignments, reversed.
 4. Taint tracking at the session level. The risky combination is: private data in context + untrusted
    content in context + a channel to an untrusted destination. When all three hold, outbound calls to untrusted
    destinations are denied even if no known secret appears in the arguments (this catches chunked or
    novel encodings the leak detector cannot see).
 5. Calls the guard cannot decide safely return NEEDS_APPROVAL; an approver callback decides (default: deny).

This reduces risk; it does not make an agent safe. See README for what it does not cover."""
from __future__ import annotations
import base64
import binascii
import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

ALLOW, DENY, NEEDS_APPROVAL = "allow", "deny", "needs_approval"


@dataclass
class ToolSpec:
    name: str
    channel: str = "none"          # "none" | "web" | "email" | "fs_write" | "fs_read"
    reads_private: bool = False
    args: Optional[Dict[str, str]] = None   # argument name -> "string"; None falls back to the built-in demo schemas


@dataclass
class Policy:
    tools: Dict[str, ToolSpec]
    sandbox_root: str = "/sandbox"
    trusted_hosts: List[str] = field(default_factory=list)       # exact host or ".suffix" entries
    trusted_email_domains: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    max_query_len: int = 0          # untrusted-host fetches may not carry a query string longer than this


@dataclass
class Decision:
    verdict: str
    reason: str
    layer: str = ""


SHINGLE = 12


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def shingles(text: str, k: int = SHINGLE) -> set:
    t = _norm(text)
    return {t[i:i + k] for i in range(max(0, len(t) - k + 1))}


@dataclass
class Session:
    has_untrusted: bool = False
    has_private: bool = False
    audit: List[Dict[str, Any]] = field(default_factory=list)
    private_shingles: set = field(default_factory=set)      # session-level content fingerprints from private results

    def derived_from_private(self, text: str) -> bool:
        """True if `text` shares a contiguous 12-character run (case/whitespace-insensitive) with private tool output.
        Catches verbatim or lightly edited copies of data the policy does not list as a secret. It does not catch
        re-encoded, paraphrased or sub-12-character fragments."""
        return bool(self.private_shingles) and not self.private_shingles.isdisjoint(shingles(urllib.parse.unquote(text)))

    @property
    def trifecta(self) -> bool:
        return self.has_untrusted and self.has_private


def _host_trusted(host: str, trusted: List[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for t in trusted:
        t = t.lower()
        if (t.startswith(".") and host.endswith(t)) or host == t:
            return True
    return False


def email_domain(addr: str) -> Optional[str]:
    """Domain of a single plain address, else None (rejects display names, multiple recipients, odd syntax)."""
    if addr.count("@") != 1 or any(c in addr for c in ", ;<>\"' \t\r\n"):
        return None
    local, dom = addr.split("@")
    dom = dom.lower().rstrip(".")
    if (not re.fullmatch(r"[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+", local)
            or local.startswith(".") or local.endswith(".") or ".." in local
            or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", dom)):
        return None
    return dom


def secret_variants(secret: str) -> List[str]:
    b = secret.encode()
    out = {secret, secret[::-1], urllib.parse.quote(secret), binascii.hexlify(b).decode(), binascii.hexlify(b).decode().upper()}
    for k, skip in ((0, 0), (1, 2), (2, 3)):       # base64 output depends on byte alignment inside the stream
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            e = enc(b"x" * k + b).decode().rstrip("=")
            out.add(e[skip:len(e) - 2] if len(e) - skip > 8 else e[skip:])
    return [v for v in out if len(v) >= 6 or (v == secret and secret)]


def leaks_secret(text: str, secrets: List[str]) -> Optional[str]:
    hay = {text, urllib.parse.unquote(text), urllib.parse.unquote_plus(text)}
    for s in secrets:
        for v in secret_variants(s):
            if any(v in h or v.lower() in h.lower() for h in hay):
                return "protected secret or encoded variant"
    return None


class Guard:
    def __init__(self, policy: Policy, approver: Optional[Callable[[str, Dict[str, Any], str], bool]] = None,
                 disabled_layers: Optional[set] = None):
        self.disabled = set(disabled_layers or ())
        if self.disabled - {"trifecta", "leak-detector", "provenance"}:
            raise ValueError("unknown ablation layer")
        # Ablation is a trusted-code experiment switch, never inferred from tool output.
        #   # for ablation studies only: 'trifecta', 'leak-detector', 'provenance'
        self.p = policy
        self.approver = approver or (lambda tool, args, why: False)

    # --- public API -------------------------------------------------
    def check(self, tool: str, args: Dict[str, Any], session: Session) -> Decision:
        d = self._decide(tool, args, session)
        if d.verdict == NEEDS_APPROVAL:
            # Approval sees a detached proposal. It cannot rewrite the validated call.
            try:
                ok = self.approver(tool, dict(args), d.reason) is True
            except Exception:
                ok = False
            d = Decision(ALLOW if ok else DENY, ("approved: " if ok else "approval refused: ") + d.reason, d.layer)
        session.audit.append({"tool": tool if isinstance(tool, str) and tool in self.p.tools else "<unknown>", "args": "<omitted: may contain private data>", "verdict": d.verdict, "reason": d.reason, "layer": d.layer,
                              "untrusted_in_context": session.has_untrusted, "private_in_context": session.has_private,
                              "destination": self._dest_summary(tool, args)})
        return d

    def _dest_summary(self, tool, args) -> str:
        """Categories only: a hostname/domain can itself carry private text."""
        spec = self.p.tools.get(tool) if isinstance(tool, str) else None
        if not spec or not isinstance(args, dict):
            return ""
        if spec.channel in ("web", "email"):
            return "<destination omitted>"
        return ""

    def observe_result(self, tool: str, untrusted: bool, private: bool, session: Session, text: str = "") -> None:
        session.has_untrusted |= untrusted
        session.has_private |= private
        if private and text:
            session.private_shingles |= shingles(text)

    # --- internals --------------------------------------------------
    def _decide(self, tool, args, s: Session) -> Decision:
        spec = self.p.tools.get(tool) if isinstance(tool, str) else None
        if spec is None:
            return Decision(DENY, "tool is not on the allowlist", "allowlist")
        # Explicit schemas for this demo's adapters. A new adapter needs a schema.
        schemas = {"read_file": {"path"}, "write_file": {"path", "content"},
                   "fetch_url": {"url"}, "send_email": {"to", "body"}, "read_inbox": set()}
        expected = set(spec.args) if spec.args is not None else schemas.get(tool)
        if (expected is None or not isinstance(args, dict) or set(args) != expected
                or any(not isinstance(v, str) for v in args.values())):
            return Decision(DENY, "invalid or unsupported tool argument schema", "schema")
        if spec.channel not in {"none", "fs_write", "fs_read", "email", "web"}:
            return Decision(DENY, "unsupported channel", "schema")
        try:
            for value in args.values():
                value.encode("utf-8")
        except UnicodeEncodeError:
            return Decision(DENY, "invalid text encoding", "schema")
        blob = " ".join(str(v) for v in args.values())
        hit = None if "leak-detector" in self.disabled else leaks_secret(blob, self.p.secrets)
        if hit and spec.channel != "none":
            return Decision(DENY, "arguments contain a protected secret (raw or encoded)", "leak-detector")
        if spec.channel in ("fs_write", "fs_read") or tool in ("read_file",):
            path = str(args.get("path", ""))
            if any(ord(c) < 32 or ord(c) == 127 for c in path):
                return Decision(DENY, "path contains controls", "path")
            norm = posixpath.normpath(path)
            root = self.p.sandbox_root.rstrip("/")
            if not (norm == root or norm.startswith(root + "/")) or ".." in path.split("/"):
                return Decision(DENY, "path escapes the sandbox", "path")
            if spec.channel == "fs_write" and s.has_untrusted and not norm.startswith(root + "/out/"):
                return Decision(NEEDS_APPROVAL, "write outside out/ while untrusted content is in context", "taint")
            return Decision(ALLOW, "path ok", "path")
        if spec.channel == "email":
            dom = email_domain(str(args.get("to", "")))
            if dom is None:
                return Decision(DENY, "recipient is not a single plain address", "recipient")
            if dom in [d.lower() for d in self.p.trusted_email_domains]:
                return Decision(ALLOW, "trusted recipient domain", "recipient")
            if s.derived_from_private(blob) and "provenance" not in self.disabled:
                return Decision(DENY, "untrusted recipient and the text is derived from private data (never approvable)", "provenance")
            if s.trifecta and "trifecta" not in self.disabled:
                return Decision(DENY, "untrusted recipient while private data and untrusted content share the context", "trifecta")
            return Decision(NEEDS_APPROVAL, "recipient domain is not trusted", "recipient")
        if spec.channel == "web":
            url = args["url"]
            if "\\" in url or any(ord(c) < 33 or ord(c) == 127 for c in url):
                return Decision(DENY, "URL contains whitespace or controls", "url")
            try:
                u = urllib.parse.urlsplit(url)
                port = u.port
            except ValueError:
                return Decision(DENY, "malformed URL", "url")
            if u.username is not None or u.password is not None or port not in (None, 80, 443):
                return Decision(DENY, "URL credentials or nonstandard port", "url")
            if u.scheme not in ("http", "https") or not u.hostname:
                return Decision(DENY, "not a valid http(s) URL", "url")
            if _host_trusted(u.hostname, self.p.trusted_hosts):
                return Decision(ALLOW, "trusted host", "url")
            if s.derived_from_private(blob) and "provenance" not in self.disabled:
                return Decision(DENY, "untrusted host and the URL text is derived from private data (never approvable)", "provenance")
            if s.trifecta and "trifecta" not in self.disabled:
                return Decision(DENY, "untrusted host while private data and untrusted content share the context", "trifecta")
            if s.has_private:
                return Decision(NEEDS_APPROVAL, "untrusted host after private data was read", "taint")
            if len(u.query) > self.p.max_query_len or u.fragment:
                return Decision(NEEDS_APPROVAL, "query/fragment on untrusted host could carry data", "url")
            return Decision(ALLOW, "read-only fetch from untrusted host, no private data in context", "url")
        return Decision(ALLOW, "no outbound channel", "none")
