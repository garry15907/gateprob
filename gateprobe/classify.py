"""관찰을 결과 하나로 분류한다.

결과
  ALLOW        도구가 실행되고 성공
  IAM_DENY     도구는 실행됐지만 백엔드 권한(IAM 등)이 거부
  POLICY_DENY  Gateway 정책 엔진이 거부 (도구까지 가지 않음)
  TOOL_ERROR   그 밖의 도구 오류 (없는 객체, 잘못된 인자 등)
  UNKNOWN      전송 오류, 정책 거부가 아닌 JSON-RPC 오류

정책 거부는 Gateway가 정하는 것이라 고정이다 (JSON-RPC 코드 policy_deny_codes, 기본 -20001).
도구 결과를 나누는 규칙은 도구마다 응답 형식이 달라서 설정으로 받는다.

규칙 설정 예
  {"policy_deny_codes": [-20001],
   "rules": [{"when": {"is_error": true}, "then": "UNKNOWN"},
             {"when": {"path": "ok", "equals": true}, "then": "ALLOW"},
             {"when": {"path": "status", "equals": "ACCESS_DENIED"}, "then": "IAM_DENY"}],
   "default": "TOOL_ERROR"}
  규칙은 위에서부터 보고 처음 맞는 것을 쓴다. when 안의 조건은 모두 맞아야 한다.

조건
  is_error: true|false         MCP 결과의 isError
  path: "a.b"                  구조화 결과에서 값을 꺼낸다. 아래 중 하나와 같이 쓴다
    equals: 값 | in: [값...] | matches: 정규식 | exists: true|false
  text_matches: 정규식         텍스트 내용 전체에서 찾는다 (대소문자 구분 없음)
"""
from __future__ import annotations

import re

OUTCOMES = ("ALLOW", "IAM_DENY", "POLICY_DENY", "TOOL_ERROR", "UNKNOWN")

# Gateway 자체 오류 문구. 도구 오류가 아니라 판정 불가로 본다 (정책 엔진 권한이 빠졌을 때 실측, 2026-11-17)
GATEWAY_INTERNAL = r"^An internal error occurred"

# 규칙을 주지 않았을 때. 응답 형식을 모르는 도구에 쓸 수 있게 텍스트에서 흔한 권한 오류 문구를 찾는다.
DEFAULT_RULES = {
    "policy_deny_codes": [-20001],
    "rules": [
        {"when": {"is_error": True, "text_matches": GATEWAY_INTERNAL}, "then": "UNKNOWN"},
        {"when": {"text_matches": r"AccessDenied|not authorized|UnauthorizedOperation|AuthorizationError|Forbidden"}, "then": "IAM_DENY"},
        {"when": {"is_error": True}, "then": "TOOL_ERROR"},
    ],
    "default": "ALLOW",
}

_MISSING = object()


def get_path(obj, path):
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return _MISSING
    return obj


def _cond_ok(cond: dict, obs: dict) -> bool:
    if "is_error" in cond and bool(obs.get("is_error")) != cond["is_error"]:
        return False
    if "text_matches" in cond and not re.search(cond["text_matches"], obs.get("text") or "", re.I):
        return False
    if "path" in cond:
        value = get_path(obs.get("output") or {}, cond["path"])
        if "exists" in cond and (value is not _MISSING) != cond["exists"]:
            return False
        if "equals" in cond and (value is _MISSING or value != cond["equals"]):
            return False
        if "in" in cond and (value is _MISSING or value not in cond["in"]):
            return False
        if "matches" in cond and (value is _MISSING or not re.search(cond["matches"], str(value))):
            return False
    return True


def classify(obs: dict, rules: dict | None = None) -> str:
    rules = rules or DEFAULT_RULES
    if obs.get("kind") == "RPC_ERROR":
        return "POLICY_DENY" if obs.get("rpc_code") in rules.get("policy_deny_codes", [-20001]) else "UNKNOWN"
    if obs.get("kind") != "TOOL_RESULT":
        return "UNKNOWN"
    for rule in rules.get("rules", []):
        conds = rule["when"] if isinstance(rule["when"], list) else [rule["when"]]
        if all(_cond_ok(c, obs) for c in conds):
            return rule["then"]
    return rules.get("default", "ALLOW")


def check_rules(rules: dict) -> list:
    """규칙 설정의 형식 오류 목록."""
    errors = []
    for i, rule in enumerate(rules.get("rules", [])):
        if rule.get("then") not in OUTCOMES:
            errors.append(f"rules[{i}].then 값이 결과 이름이 아님: {rule.get('then')}")
        conds = rule.get("when")
        conds = conds if isinstance(conds, list) else [conds]
        for c in conds:
            if not isinstance(c, dict) or not c:
                errors.append(f"rules[{i}].when 형식 오류")
                continue
            unknown = set(c) - {"is_error", "text_matches", "path", "equals", "in", "matches", "exists"}
            if unknown:
                errors.append(f"rules[{i}].when 모르는 조건: {sorted(unknown)}")
            for key in ("text_matches", "matches"):
                if key in c:
                    try:
                        re.compile(c[key])
                    except re.error as exc:
                        errors.append(f"rules[{i}].when.{key} 정규식 오류: {exc}")
            if any(k in c for k in ("equals", "in", "matches", "exists")) and "path" not in c:
                errors.append(f"rules[{i}].when: equals/in/matches/exists에는 path가 필요함")
    if rules.get("default", "ALLOW") not in OUTCOMES:
        errors.append(f"default 값이 결과 이름이 아님: {rules.get('default')}")
    return errors
