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
import sys
from pathlib import Path

# The plugin loader does not put our directory on sys.path (errors.log:
# "Failed to load plugin 'keygate': No module named 'keygate_lib'"), so pin
# it explicitly before importing our sibling module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
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
                    ["keepassxc-cli", "show", "-k", kf, "--no-password", "-q",
                     *([] if field != "totp" else ["-t"]), "-s",
                     *([] if field == "totp" else ["-a", _attr(field)]),
                     "--", db, alias],
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
    return {"username": "UserName", "url": "URL", "password": "Password"}.get(field, "Password")


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


def _channel_diag() -> dict:
    """How could we reach the human? Booleans + platform only, never secrets
    or full session keys. Lets remote debugging happen via chat paste."""
    d: dict = {"session": False, "platform": None, "cron": False,
               "single_query": False, "gateway": False,
               "interactive_cli": False, "notify_cb": False}
    try:
        from tools import approval_context as _ctx
        try:
            d["session"] = bool(_ctx.get_current_session_key())
        except Exception:
            pass
        try:
            d["platform"] = str(_ctx._get_session_platform())
        except Exception:
            pass
        for k, fn in (("cron", "_is_cron_approval_context"),
                      ("single_query", "_is_single_query_approval_context"),
                      ("gateway", "_is_gateway_approval_context"),
                      ("interactive_cli", "_is_interactive_cli")):
            try:
                d[k] = bool(getattr(_ctx, fn)())
            except Exception:
                pass
        if d["gateway"] and d["session"]:
            try:
                from tools import approval as _a
                d["notify_cb"] = bool(_a._gateway_notify_cb(_ctx.get_current_session_key()))
            except Exception:
                pass
    except Exception:
        pass
    return d


def _version_info() -> dict:
    """Installed vs repo version for Hermes: update notices + changelog.
    Updates never touch vaults (enforced in scripts/keygate-update)."""
    here = Path(__file__).resolve().parent
    info: dict = {"installed_version": "unknown", "installed_commit": "unknown",
                  "repo_head": None, "repo_version": None,
                  "update_available": False, "changelog": []}
    try:
        for line in (here / "plugin.yaml").read_text().splitlines():
            if line.strip().startswith("version:"):
                info["installed_version"] = line.split(":", 1)[1].strip().strip('"')
    except Exception:
        pass
    try:
        info["installed_commit"] = (here / ".installed_commit").read_text().strip()[:12]
    except Exception:
        pass
    repo = Path.home() / "hermes-keygate"
    try:
        import subprocess as _sp
        head = _sp.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, timeout=10).stdout.strip()
        if head:
            info["repo_head"] = head[:12]
            for line in (repo / "plugin.yaml").read_text().splitlines():
                if line.strip().startswith("version:"):
                    info["repo_version"] = line.split(":", 1)[1].strip().strip('"')
            inst = info["installed_commit"]
            if inst and inst != "unknown" and not head.startswith(inst):
                info["update_available"] = True
                log = _sp.run(["git", "-C", str(repo), "log", "--format=%s",
                               f"{inst}..HEAD", "--max-count=5"],
                              capture_output=True, text=True, timeout=10).stdout
                info["changelog"] = [l for l in log.splitlines() if l.strip()][:5]
            elif (info["repo_version"] and info["installed_version"] != "unknown"
                    and info["repo_version"] != info["installed_version"]):
                info["update_available"] = True
    except Exception:
        pass
    return info


def register(ctx):
    ctx.register_secret_source(KeepassSource())
    try:
        _vi = _version_info()
        if _vi.get("update_available"):
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "keygate update available: installed %s (%s) -> repo %s (%s). "
                "Run scripts/keygate-update. Updates never touch .kdbx/.key. %s",
                _vi.get("installed_version"), _vi.get("installed_commit"),
                _vi.get("repo_version"), _vi.get("repo_head"),
                "; ".join(_vi.get("changelog", []))[:300])
    except Exception:
        pass

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

        # 1) Human approval on the active session's own surface
        # (gateway buttons / CLI panel / Desktop) via the sanctioned
        # elicitation API — the same path native vault uses for card fills.
        # Unattended contexts (cron, -q) cannot prompt: refuse immediately
        # with a distinct error instead of a silent decline.
        _ch = _channel_diag()
        if _ch.get("cron") or _ch.get("single_query"):
            return json.dumps({"success": False, "error_type": "unattended",
                               "error": ("this session cannot prompt (cron/one-shot): "
                                         "run from an interactive CLI/Desktop/Telegram session")})
        try:
            from tools.approval_prompt import request_elicitation_consent
            decision = request_elicitation_consent(
                f"Fill login {kg.redact_label(alias)} on {kg.redact_origin(origin)}?",
                ("Hermes wants KeePass to enter this site's username and password "
                 "into the page (TOTP too when the entry has a seed). Secrets never "
                 "enter the chat, logs or memory — only this prompt. One-time use: "
                 "the next fill asks again."),
                surface="keygate-fill", title="Allow credential fill?")
        except Exception as exc:
            return json.dumps({"success": False, "error": f"approval unavailable: {exc}"})
        approval_evidence = {"approval": str(decision)}
        if decision != "accept":
            kg.audit(_home(), {"ev": "fill", "alias": kg.redact_label(alias),
                               "origin": kg.redact_origin(origin), "decision": "deny",
                               **approval_evidence})
            return json.dumps({"success": False, "error": "user denied (explicit approval required)",
                               "error_type": "denied", "channel": _ch})

        # 2-4) Blind fill through the native secret-safe path (exact-origin
        # binding, inspect+classify, CDP WebSocket only, redaction boundary).
        # Username also fills server-side so the full identifier never enters
        # the conversation (strict redaction).
        filled = _native_keygate_fill(kw.get("task_id") or params.get("task_id") or "default",
                                      alias, origin, db, kf)
        kg.audit(_home(), {"ev": "fill", "alias": kg.redact_label(alias),
                           "origin": kg.redact_origin(origin),
                           "decision": "allow" if filled.get("success") else filled.get("error_type", "refused"),
                           "filled": filled.get("filled_fields", 0),
                           "totp": filled.get("totp_filled", False),
                           **approval_evidence})
        out = {"success": bool(filled.get("success")), "filled_fields": filled.get("filled_fields", 0),
               "origin": filled.get("origin", origin), "totp_filled": filled.get("totp_filled", False)}
        if not out["success"]:
            out["error"] = filled.get("error", "fill refused")
        return json.dumps(out)

    ctx.register_tool(
        name="keygate_request_fill",
        toolset="keygate",
        schema={"name": "keygate_request_fill",
                "description": ("Request a blind login fill. FIRST navigate to the login page "
                                "with browser_navigate (agent browser, not Desktop preview). Shows "
                                "an approval prompt on YOUR screen (accept = one-time fill, anything "
                                "else denies); checks vault-URL == page origin, resolves KeePass "
                                "server-side and fills user+password (+TOTP) via CDP. "
                                "AFTER a successful fill, submit the SAME form without re-navigating "
                                "(re-navigate clears the filled values), then read the flash message. "
                                "Returns {success, filled_fields} only — password/TOTP never appear in results."),
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

    # ---- keygate_version: update notices for Hermes ----
    def h_version(params, **kw):
        del params, kw
        return json.dumps({"success": True, **_version_info()})

    ctx.register_tool(
        name="keygate_version",
        toolset="keygate",
        schema={"name": "keygate_version",
                "description": ("Installed vs repo version, update_available flag and changelog. "
                                "Call it when starting credential work: if update_available is true, "
                                "tell the user to run scripts/keygate-update. Updates never touch "
                                ".kdbx/.key (enforced by the updater)."),
                "parameters": {"type": "object", "properties": {}, "required": []}},
        handler=h_version)

    # ---- keygate_doctor: remote diagnostics without secrets ----
    def h_doctor(params, **kw):
        del params, kw
        cfg = _plug_cfg()
        db, kf = kg.cfg_paths(cfg)
        locked = kg.db_locked(db, kf)
        out = {"success": True, "version": _version_info(),
               "db": {"locked": locked,
                      "entries": 0 if locked else len(kg.list_entries(db, kf))},
               "channel": _channel_diag(), "audit_tail": []}
        try:
            lines = (_home() / "keygate-audit.jsonl").read_text().splitlines()[-3:]
            out["audit_tail"] = lines
        except Exception:
            pass
        return json.dumps(out)

    ctx.register_tool(
        name="keygate_doctor",
        toolset="keygate",
        schema={"name": "keygate_doctor",
                "description": ("Diagnose this host without secrets: plugin version/update, "
                                "operative DB locked + entry count, approval channel reachability "
                                "(platform, gateway notify), last redacted audit lines. Paste the "
                                "result when reporting problems."),
                "parameters": {"type": "object", "properties": {}, "required": []}},
        handler=h_doctor)

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

    # ---- keygate_alias_add: BLOCKED by policy (no secret creation from chat) ----
    def h_add(params, **kw):
        del params, kw
        return json.dumps({"success": False, "error_type": "policy_blocked",
                           "error": ("Adding credentials from chat is disabled: passwords must never "
                                     "travel through chat history. Add the copy in your local KeePassXC "
                                     "and sync the .kdbx via keygate-sync web or keygate-push/pull (croc).")})

    ctx.register_tool(
        name="keygate_alias_add",
        toolset="keygate",
        schema={"name": "keygate_alias_add",
                "description": "ALWAYS REFUSED by policy. Credentials are never created from chat.",
                "parameters": {"type": "object", "properties": {}, "required": []}},
        handler=h_add)


def _native_keygate_fill(task_id: str, alias: str, origin: str, db: str, kf: str) -> dict:
    """Blind fill through Hermes' native secret-safe machinery.

    Mirrors tools.browser_vault_fill but resolves user/pass/TOTP from the
    operative KeePassXC DB instead of a LoginBackend:
    - exact-origin binding (vault URL == requested origin == page origin,
      re-asserted inside the fill script against TOCTOU)
    - inspect + classify page controls; identifier + password (+TOTP) filled
      via supervisor CDP WebSocket only (never argv)
    - register_vault_redaction_value BEFORE touching the page; errors scrubbed
    Returns {success, filled_fields, origin, totp_filled} — never secrets.
    """
    import secrets as _secrets
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import (
        LoginControl, build_fill_js, build_inspection_js, build_otp_fills,
        classify_login_control, classify_otp_controls, select_password_fill)
    from agent.vault_store import normalize_origin, scrub_secret_from_text
    from tools.browser_vault_tool import (
        _current_page_origin, _eval_js, _eval_js_secret,
        _focus_bound_origin, _parse_json_result)
    try:
        from tools.browser_tool import _last_session_key
    except Exception:
        def _last_session_key(tid):  # fallback: no remap
            return tid or "default"

    def _resolve_effective_task(tid):
        # Existing supervisors first (no session creation, no cloud charge
        # attempts); single creation-attempt probe afterwards at most.
        try:
            from tools.browser_supervisor import SUPERVISOR_REGISTRY
        except Exception:
            SUPERVISOR_REGISTRY = None
        cands = []
        for cand in (tid, _last_session_key(tid or "default"),
                     "default", _last_session_key("default")):
            cand = cand or "default"
            if cand not in cands:
                cands.append(cand)
        if SUPERVISOR_REGISTRY is not None:
            for cand in cands:
                try:
                    if SUPERVISOR_REGISTRY.get(cand) and _current_page_origin(cand):
                        return cand
                except Exception:
                    continue
        best = _last_session_key(tid or "default")
        try:
            if _current_page_origin(best):
                return best
        except Exception:
            pass
        return best

    task_id = _resolve_effective_task(task_id)

    entry_url = kg.show_field(db, kf, alias, "url") or ""
    try:
        bound = normalize_origin(entry_url) if entry_url else ""
    except Exception:
        bound = ""
    if bound and origin.lower() not in bound.lower() and bound.lower() not in origin.lower():
        return {"success": False, "filled_fields": 0, "origin": origin,
                "error_type": "domain_mismatch",
                "error": "vault URL != requested origin — refused"}
    allowed = [bound] if bound else [origin]

    page_origin = None
    for candidate in allowed:
        try:
            page_origin = _focus_bound_origin(task_id, candidate, "login")
        except Exception:
            page_origin = None
        if page_origin:
            break
    try:
        page_origin = page_origin or _current_page_origin(task_id)
    except Exception as exc:
        return {"success": False, "filled_fields": 0, "origin": origin, "error": str(exc)[:200]}
    if not page_origin:
        return {"success": False, "filled_fields": 0, "origin": origin,
                "error": ("no page open in the agent browser — navigate with browser_navigate "
                          "(not the Desktop preview panel) to the login page first, then retry")}
    if page_origin not in allowed:
        return {"success": False, "filled_fields": 0, "origin": origin,
                "error_type": "origin_mismatch",
                "error": f"page {page_origin!r} != bound {', '.join(allowed)} — refused"}

    username = kg.show_field(db, kf, alias, "username") or ""
    pw_raw = kg.show_field(db, kf, alias, "password") or ""
    if not pw_raw:
        return {"success": False, "filled_fields": 0, "origin": page_origin,
                "error": "no password for alias"}
    pw_b = bytearray(pw_raw.encode("utf-8"))
    pw_raw = ""
    secret = {"password": bytes(pw_b).decode("utf-8", errors="replace"),
              "username": username}

    try:
        nonce = _secrets.token_hex(8)
        inspect = _eval_js(task_id, build_inspection_js(nonce))
        if not inspect.get("success"):
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": f"inspect failed: {inspect.get('error', '')[:150]}"}
        raw = _parse_json_result(inspect.get("result"))
        if isinstance(raw, str):
            raw = _parse_json_result(raw)
        if not isinstance(raw, list):
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": "no usable controls on page"}
        classified = [c for c in
                      (classify_login_control(LoginControl.from_dict(r)) for r in raw
                       if isinstance(r, dict)) if c is not None]
        if not classified:
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": "no login fields found"}
        fills = select_password_fill(classified, secret["password"])
        if username:
            ids = [c for c in classified if c.token in ("username", "email", "tel")]
            if ids:
                best = sorted(ids, key=lambda c: (-c.score, c.control.index))[0]
                fills = [{"index": best.control.index, "token": best.token,
                          "value": username}] + fills
        if not fills:
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": "no fillable field matched"}

        register_vault_redaction_value(secret["password"])
        if username:
            register_vault_redaction_value(username)
        try:
            fr = _eval_js_secret(task_id, build_fill_js(fills, expected_origin=page_origin, nonce=nonce))
        except Exception as exc:
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": scrub_secret_from_text(str(exc), secret)}
        if not fr.get("success"):
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error": scrub_secret_from_text(str(fr.get("error") or "fill failed"), secret)}
        parsed = _parse_json_result(fr.get("result"))
        if isinstance(parsed, str):
            parsed = _parse_json_result(parsed)
        if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
            return {"success": False, "filled_fields": 0, "origin": page_origin,
                    "error_type": "origin_changed",
                    "error": "page navigated away before fill — nothing written"}
        filled = int(parsed.get("filled", 0)) if isinstance(parsed, dict) else 0

        totp_filled = False
        otp_code = kg.show_field(db, kf, alias, "totp")
        if otp_code and filled:
            otp_controls = classify_otp_controls(
                [LoginControl.from_dict(r) for r in raw if isinstance(r, dict)])
            otp_fills = build_otp_fills(otp_controls, otp_code) if otp_controls else []
            if otp_fills:
                register_vault_redaction_value(otp_code)
                try:
                    or_ = _eval_js_secret(task_id, build_fill_js(otp_fills, expected_origin=page_origin,
                                                                 nonce=nonce))
                    op = _parse_json_result(or_.get("result"))
                    if isinstance(op, str):
                        op = _parse_json_result(op)
                    totp_filled = bool(or_.get("success") and isinstance(op, dict)
                                       and int(op.get("filled", 0)) > 0)
                except Exception:
                    totp_filled = False
            kg.zeroize(bytearray(otp_code.encode()))
        return {"success": bool(filled), "filled_fields": filled,
                "origin": page_origin, "totp_filled": totp_filled}
    finally:
        kg.zeroize(pw_b)
        secret["password"] = ""
        secret["username"] = ""
