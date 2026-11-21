"""Declarative policy files (JSON) with strict validation. Secrets are not read from the file by default: pass them in code
(`load_policy(path, secrets=[...])`) so the policy file can be reviewed and committed without credentials in it."""
from __future__ import annotations
import json
import re
import posixpath
from typing import Any, Dict, List, Optional

from .guard import Policy, ToolSpec

CHANNELS = {"none", "web", "email", "fs_write", "fs_read"}
REQUIRED_ARGS = {"web": {"url"}, "email": {"to", "body"}, "fs_write": {"path", "content"}, "fs_read": {"path"}}
NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
HOST = re.compile(r"^\.?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
TOP = {"sandbox_root", "trusted_hosts", "trusted_email_domains", "max_query_len", "tools"}
TOOL_KEYS = {"channel", "reads_private", "args"}


class PolicyError(ValueError):
    pass


def parse_policy(doc: Any, secrets: Optional[List[str]] = None) -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a JSON object")
    extra = set(doc) - TOP
    if extra:
        raise PolicyError(f"unknown top-level keys: {sorted(extra)}")
    root = doc.get("sandbox_root", "/sandbox")
    if not isinstance(root, str) or not root.startswith("/") or root.rstrip("/") == "" or ".." in root.split("/"):
        raise PolicyError("sandbox_root must be an absolute path other than '/' without '..'")
    hosts = doc.get("trusted_hosts", [])
    if not isinstance(hosts, list) or any(not isinstance(h, str) or not HOST.fullmatch(h) for h in hosts):
        raise PolicyError("trusted_hosts entries must be lowercase hostnames or '.suffix' (no scheme, path, port or bare TLD)")
    if any(h.count(".") < 2 and h.startswith(".") for h in hosts):
        raise PolicyError("a '.suffix' trusted host must have at least two labels (for example .corp.example)")
    doms = doc.get("trusted_email_domains", [])
    if not isinstance(doms, list) or any(not isinstance(d, str) or "@" in d or not HOST.fullmatch(d) or d.startswith(".") for d in doms):
        raise PolicyError("trusted_email_domains entries must be plain domains without '@'")
    mq = doc.get("max_query_len", 0)
    if not isinstance(mq, int) or isinstance(mq, bool) or mq < 0:
        raise PolicyError("max_query_len must be a non-negative integer")
    tools_raw = doc.get("tools")
    if not isinstance(tools_raw, dict) or not tools_raw:
        raise PolicyError("tools must be a non-empty object")
    canonical = {"read_file": "fs_read", "fetch_url": "web", "read_inbox": "none", "send_email": "email", "write_file": "fs_write"}
    tools: Dict[str, ToolSpec] = {}
    for name, t in tools_raw.items():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise PolicyError(f"tool name {name!r} must be lowercase letters, digits and underscores")
        if not isinstance(t, dict) or set(t) - TOOL_KEYS:
            raise PolicyError(f"tool {name}: unknown keys {sorted(set(t) - TOOL_KEYS) if isinstance(t, dict) else t}")
        ch = t.get("channel", "none")
        if not isinstance(ch, str) or ch not in CHANNELS:
            raise PolicyError(f"tool {name}: channel must be one of {sorted(CHANNELS)}")
        args = t.get("args")
        if not isinstance(args, dict) or any(not isinstance(k, str) or v != "string" for k, v in args.items()):
            raise PolicyError(f"tool {name}: args must be an object mapping names to \"string\" (the only supported type)")
        need = REQUIRED_ARGS.get(ch, set())
        if not need <= set(args):
            raise PolicyError(f"tool {name}: channel {ch} needs args {sorted(need)}")
        if ch in REQUIRED_ARGS and set(args) != need:
            raise PolicyError(f"tool {name}: channel {ch} permits only args {sorted(need)}")
        if name in canonical and ch != canonical[name]:
            raise PolicyError(f"tool {name}: known adapter channel must be {canonical[name]}")
        if name == "read_inbox" and args:
            raise PolicyError("read_inbox takes no arguments")
        rp = t.get("reads_private", False)
        if not isinstance(rp, bool):
            raise PolicyError(f"tool {name}: reads_private must be true or false")
        tools[name] = ToolSpec(name, ch, rp, dict(args))
    return Policy(tools=tools, sandbox_root=posixpath.normpath(root), trusted_hosts=list(hosts), trusted_email_domains=list(doms),
                  secrets=list(secrets or []), max_query_len=mq)


def load_policy(path: str, secrets: Optional[List[str]] = None) -> Policy:
    with open(path, encoding="utf-8") as f:
        try:
            return parse_policy(json.load(f), secrets)
        except json.JSONDecodeError as e:
            raise PolicyError(f"{path}: not valid JSON ({e})")
