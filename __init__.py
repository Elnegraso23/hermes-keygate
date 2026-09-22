"""hermes-keygate plugin: blind KeePassXC injector (Plan A thin adapter).

- SecretSource `keepass` (mapped, scheme kpx://) for API keys at startup.
  Refs: kpx://alias/password|username|totp|url. Operative DB is keyfile-only
  (--no-password), so Hermes NEVER receives a master password.
- Tools the model sees (metadata or ok only, never secrets):
  - keygate_search(query) -> [{alias, hint}] redacted
  - keygate_request_fill(alias, origin) -> approval via clarify, then
    server-side resolve + supervised CDP fill, returns {ok, filled_fields}
  - keygate_status() -> {unlocked, entries} (counts only)
  - keygate_session_ensure(domain, ttl) / keygate_session_invalidate(domain)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
)

import keygate_lib as kg


# ---------------------------------------------------------- SecretSource ---

class KeepassSource(SecretSource):
    name = "keepass"
    label = "KeePassXC (keygate)"
    shape = "mapped"
    scheme = "kpx"

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "db_path": {"description": "Operative hermes.kdbx path", "default": kg.DEFAULT_DB},
            "keyfile": {"description": "Keyfile for operative DB (keyfile-only, no master)", "default": kg.DEFAULT_KEYFILE},
            "env": {"description": "Map ENV_VAR -> kpx://alias/field", "default": {}},
            "timeout_seconds": {"description": "Fetch budget", "default": 30},
        }

    def remediation(self, kind, cfg: dict) -> str:
        if kind == ErrorKind.NOT_CONFIGURED:
            return "Set secrets.keepass.db_path/keyfile/env; unlock hermes.kdbx in KeePassXC first."
        if kind in (ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED):
            return "Operative DB locked or keyfile wrong — unlock hermes.kdbx locally (1 click, keyfile-only)."
        if kind == ErrorKind.BINARY_MISSING:
            return "apt install keepassxc (provides keepassxc-cli)."
        return super().remediation(kind, cfg)

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}
        refs = cfg.get("env") or {}
        if not isinstance(refs, dict) or not refs:
            return result.fail("secrets.keepass.enabled but secrets.keepass.env is empty.",
                               ErrorKind.NOT_CONFIGURED)
        db, kf = kg.cfg_paths(cfg)
        if not Path(db).is_file():
            return result.fail(f"operative DB not found: {db}", ErrorKind.NOT_CONFIGURED)
        if not Path(kf).is_file():
            return result.fail("keyfile not found — create ~/.keepass-agent.key first.",
                               ErrorKind.NOT_CONFIGURED)
        valid: Dict[str, tuple] = {}
        for name, ref in refs.items():
            if not is_valid_env_name(name):
                result.warnings.append(f"Skipping {name!r}: bad env name")
                continue
            parsed = kg.parse_kpx_ref(ref) if isinstance(ref, str) else None
            if not parsed:
                result.warnings.append(f"Skipping {name!r}: want kpx://alias/field")
                continue
            valid[name] = parsed
        if not valid:
            return result.fail("no valid kpx:// references.", ErrorKind.REF_INVALID)
        if kg.db_locked(db, kf):
            return result.fail("operative DB locked — unlock hermes.kdbx locally first.",
                               ErrorKind.AUTH_EXPIRED)
        secrets: Dict[str, str] = {}
        for name, (alias, field) in valid.items():
            try:
                proc = run_secret_cli(
                    ["keepassxc-cli", "--no-password", "-k", kf, "-q",
                     *([] if field != "totp" else ["-t"]), "-s",
                     *([] if field in ("totp", "password") else ["-a", _attr(field)]),
                     "show", "--", db, alias],
                    allow_env=(), timeout=30.0)
            except RuntimeError as exc:
                result.warnings.append(f"{name}: helper failed ({exc})")
                continue
            if proc.returncode != 0:
                result.warnings.append(f"{name}: alias {alias!r} not found/locked")
                continue
            val = (proc.stdout or "").strip()
            if not val:
                result.warnings.append(f"{name}: empty value")
                continue
            secrets[name] = val
            _burn(proc.stdout)
        result.secrets = secrets
        return result


def _attr(field: str) -> str:
    return {"username": "UserName", "url": "URL"}.get(field, "Password")


def _burn(s: str) -> None:
    try:
        b = bytearray(s.encode("utf-8"))
        kg.zeroize(b)
        del b
    except Exception:
        pass


# ------------------------------------------------------------------ tools ---

def _plug_cfg() -> dict:
    try:
        from hermes_cli.config import load_config_readonly
        sec = (load_config_readonly().get("secrets") or {}).get("keepass") or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:
        return {}


def _home() -> Path:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def register(ctx):
    ctx.register_secret_source(KeepassSource())

    # ---- keygate_search: redacted metadata only ----
    def h_search(params, **kw):
        del kw
        cfg = _plug_cfg()
        db, kf = kg.cfg_paths(cfg)
        q = str((params or {}).get("query") or "").strip().lower()
        if kg.db_locked(db, kf):
            return json.dumps({"success": False, "locked": True,
                               "error": "operative DB locked — unlock hermes.kdbx locally"})
        out = []
        for entry in kg.list_entries(db, kf):
            alias = entry.split("/")[-1]
            if q and q not in alias.lower() and q not in entry.lower():
                continue
            out.append({"alias": alias, "hint": kg.hint_for(alias, ""),
                        "group": entry.rsplit("/", 1)[0] if "/" in entry else ""})
        return json.dumps({"success": True, "items": out[:50], "count": len(out)})

    ctx.register_tool(
        name="keygate_search",
        toolset="keygate",
        schema={"name": "keygate_search",
                "description": ("Search operative KeePass aliases. Returns redacted hints "
                                "{alias, hint} only — never passwords. Use alias with "
                                "keygate_request_fill after user approval."),
                "parameters": {"type": "object",
                               "properties": {"query": {"type": "string"}},
                               "required": []}},
        handler=h_search)

    # ---- keygate_request_fill: clarify approval + server-side CDP fill ----
    def h_fill(params, **kw):
        params = params or {}
        alias = str(params.get("alias") or "").strip()
        origin = str(params.get("origin") or "").strip()
        if not alias or not origin:
            return json.dumps({"success": False, "error": "alias and origin required"})
        cfg = _plug_cfg()
        db, kf = kg.cfg_paths(cfg)
        if kg.db_locked(db, kf):
            return json.dumps({"success": False, "locked": True,
                               "error": "operative DB locked — unlock hermes.kdbx locally"})

        # 1) Human approval via clarify (CLI/Telegram/Desktop surface).
        # The secret is NOT in this prompt — only redacted hint.
        try:
            res = ctx.dispatch_tool("clarify", {
                "questions": [{
                    "question": (f"Allow Hermes to fill login {kg.redact_label(alias)} "
                                 f"on {kg.redact_origin(origin)}?"),
                    "choices": ["once (Recommended)", "session 15min", "deny"],
                }]})
            ans = json.loads(res) if isinstance(res, str) else res
            text = json.dumps(ans).lower()
            if "deny" in text or "timeout" in text or "did not provide" in text:
                kg.audit(_home(), {"ev": "fill", "alias": kg.redact_label(alias),
                                   "origin": kg.redact_origin(origin), "decision": "deny"})
                return json.dumps({"success": False, "error": "user denied"})
        except Exception as exc:
            return json.dumps({"success": False, "error": f"approval unavailable: {exc}"})

        # 2) Origin binding: entry URL must match requested origin.
        entry_url = kg.show_field(db, kf, alias, "url") or ""
        if entry_url and origin.lower() not in entry_url.lower() \
                and entry_url.lower() not in origin.lower():
            kg.audit(_home(), {"ev": "fill", "alias": kg.redact_label(alias),
                               "origin": kg.redact_origin(origin), "decision": "domain-mismatch"})
            return json.dumps({"success": False,
                               "error": "domain mismatch — vault URL != tab origin"})

        # 3) Resolve server-side (process memory only).
        pw_b = bytearray((kg.show_field(db, kf, alias, "password") or "").encode())
        un = kg.show_field(db, kf, alias, "username") or ""
        if not pw_b:
            return json.dumps({"success": False, "error": "no password for alias"})

        # 4) Fill over supervised CDP WebSocket (never argv). Reuse native vault
        # fill when available; otherwise refuse rather than leak via argv.
        filled = _cdp_fill(kw.get("task_id") or params.get("task_id") or "cli",
                           un, pw_b, origin)
        kg.zeroize(pw_b)
        del pw_b
        otp = kg.show_field(db, kf, alias, "totp")
        totp_ok = False
        if otp and filled.get("success"):
            totp_ok = bool(_cdp_fill_totp(kw.get("task_id") or "cli", otp).get("success"))
            kg.zeroize(bytearray(otp.encode()))
        kg.audit(_home(), {"ev": "fill", "alias": kg.redact_label(alias),
                           "origin": kg.redact_origin(origin), "decision": "allow",
                           "filled": filled.get("filled_fields", 0), "totp": totp_ok})
        out = {"success": bool(filled.get("success")), "filled_fields": filled.get("filled_fields", 0),
               "origin": origin, "totp_filled": totp_ok}
        if not out["success"]:
            out["error"] = filled.get("error", "fill refused")
        return json.dumps(out)

    ctx.register_tool(
        name="keygate_request_fill",
        toolset="keygate",
        schema={"name": "keygate_request_fill",
                "description": ("Request a blind login fill. Asks the user (once/session/deny), "
                                "checks vault-URL == page origin, resolves KeePass server-side "
                                "and fills via CDP. Returns {success, filled_fields} only — "
                                "password/TOTP never appear in results."),
                "parameters": {"type": "object",
                               "properties": {"alias": {"type": "string"},
                                              "origin": {"type": "string"}},
                               "required": ["alias", "origin"]}},
        handler=h_fill)

    # ---- keygate_status ----
    def h_status(params, **kw):
        del params, kw
        cfg = _plug_cfg()
        db, kf = kg.cfg_paths(cfg)
        locked = kg.db_locked(db, kf)
        n = 0 if locked else len(kg.list_entries(db, kf))
        return json.dumps({"success": True, "locked": locked, "entries": n,
                           "db": kg.redact_origin(db)})

    ctx.register_tool(
        name="keygate_status",
        toolset="keygate",
        schema={"name": "keygate_status",
                "description": "Operative KeePass status: locked? how many aliases? (counts only)",
                "parameters": {"type": "object", "properties": {}, "required": []}},
        handler=h_status)

    # ---- sessions (ephemeral TTL, no secrets stored) ----
    def h_sess_ensure(params, **kw):
        del kw
        p = params or {}
        r = kg.session_ensure(str(p.get("domain") or ""),
                              int(p.get("ttl_seconds") or 14400))
        return json.dumps({"success": True, **r})

    def h_sess_inv(params, **kw):
        del kw
        ok = kg.session_invalidate(str((params or {}).get("domain") or ""))
        return json.dumps({"success": True, "invalidated": ok})

    ctx.register_tool(
        name="keygate_session_ensure",
        toolset="keygate",
        schema={"name": "keygate_session_ensure",
                "description": "Get/refresh an opaque ephemeral session handle for a domain (TTL, no secrets stored).",
                "parameters": {"type": "object",
                               "properties": {"domain": {"type": "string"},
                                              "ttl_seconds": {"type": "number"}},
                               "required": ["domain"]}},
        handler=h_sess_ensure)
    ctx.register_tool(
        name="keygate_session_invalidate",
        toolset="keygate",
        schema={"name": "keygate_session_invalidate",
                "description": "Invalidate an ephemeral session (call on 401/redirect to login; never retry with expired tokens).",
                "parameters": {"type": "object",
                               "properties": {"domain": {"type": "string"}},
                               "required": ["domain"]}},
        handler=h_sess_inv)


def _cdp_fill(task_id: str, username: str, pw_b: bytearray, origin: str) -> dict:
    """Server-side fill over supervisor CDP WebSocket. Secret bytes travel only
    inside the CDP message, never argv/logs/results. Falls back to refusal."""
    try:
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        sup = SUPERVISOR_REGISTRY.get(task_id)
        if sup is None:
            return {"success": False, "error": "no supervised browser session — open Hermes browser first",
                    "filled_fields": 0}
        cur = sup.evaluate_runtime("JSON.stringify({o: location.origin})")
        page_origin = ""
        try:
            page_origin = json.loads(cur.get("result") or "{}").get("o", "")
        except Exception:
            page_origin = ""
        if origin.lower() not in page_origin.lower() and page_origin.lower() not in origin.lower():
            return {"success": False, "error": f"page origin {page_origin!r} != {origin!r}",
                    "filled_fields": 0}
        # NOTE: real fill uses the supervisor's secret-safe runtime call
        # (same path as browser_vault_fill). This thin adapter delegates to it
        # when present so secret bytes never touch argv.
        fill = getattr(sup, "fill_login", None)
        if callable(fill):
            password = bytes(pw_b).decode("utf-8", errors="replace")
            try:
                r = fill(username=username, password=password, origin=origin)
            finally:
                password = ""
            if isinstance(r, dict):
                return {"success": bool(r.get("ok", True)),
                        "filled_fields": int(r.get("filled_fields", 2))}
            return {"success": True, "filled_fields": 2}
        return {"success": False, "filled_fields": 0,
                "error": "supervisor has no secret-safe fill — refusing rather than argv leak"}
    except Exception as exc:
        return {"success": False, "filled_fields": 0, "error": str(exc)[:200]}


def _cdp_fill_totp(task_id: str, code: str) -> dict:
    try:
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        sup = SUPERVISOR_REGISTRY.get(task_id)
        if sup is None:
            return {"success": False}
        fill = getattr(sup, "fill_totp", None)
        if callable(fill):
            r = fill(code=code)
            return {"success": bool((r or {}).get("ok", True))}
        return {"success": False}
    except Exception:
        return {"success": False}
