"""대상 파일과 시나리오 파일 읽기, 변수 치환, 기대값 해석, 형식 검사.

대상 파일 (배포 하나를 설명. 계정마다 다름)
  name            이름
  region          AWS 리전
  profile         AWS 프로필 (없으면 기본 자격 증명 체인. CI에서는 비워 둔다)
  auth            {"type": "sigv4"} (기본) | {"type": "bearer", "token_env": "GW_TOKEN"}
                  | {"type": "oauth", "token_url": "https://.../oauth2/token", "client_id_env": "GW_CLIENT_ID",
                     "client_secret_env": "GW_CLIENT_SECRET", "scope": "선택"}  (gateprobe가 토큰을 받고 갱신)
  mcp_version     Gateway에 보낼 MCP 버전. "2026-07-28"(기본) | "2025-11-25". Gateway가 받는 버전이어야 한다
                  (init이 Gateway 설정을 읽어 적는다)
  gateways        {"이름": "https://.../mcp"}. 값에 {변수}나 "env:환경변수"를 쓸 수 있다
  vars            시나리오에서 쓸 변수 {"이름": "값"}
  vars_file       변수를 읽을 JSON 파일 (git에 넣지 않을 계정 정보). 문자열 값만 변수가 된다.
                  gateways를 적지 않으면 이 파일의 "gateways"를 쓴다
  inject_args     모든 호출 인자에 더할 값 (예: {"run_id": "{run}"}). 도구 계약이 요구할 때
  classify        분류 규칙 (classify.py 참고). 없으면 기본 규칙
  policy_id_pattern  정책 거부 메시지에서 정책 ID를 뽑는 정규식
  fixture_profile 사전 객체를 올릴 때 쓸 AWS 프로필 (없으면 profile)
  labels          HTML 보고서에 쓸 Gateway 표시 이름 {"이름": "표시 이름"}
  tool_labels     HTML 보고서에 쓸 도구 표시 이름 {"read_file": "읽기"}

시나리오 파일 (점검할 호출과 기대. 배포와 무관하게 씀)
  name, target(도구 이름 앞부분. "t01-tools"면 read_file은 t01-tools___read_file)
  fixtures   [{"type": "s3", "bucket", "key", "body" 또는 "body_file"}]  시나리오마다 새로 올림
  scenarios  [{"id", "steps": [{"tool", "args", "expect"}]}]  한 시나리오는 한 정책 세션
             단계별 "wait": 초. 그 호출 전에 기다린다 (앞 호출 기록이 정책 엔진에 보이기까지, "5분 뒤" 같은 시간 조건)
             보고서용(선택): "제목"(짧게), "요약"(한 줄), "분류"(묶음 이름), "설명"(긴 설명)
  분류       보고서용(선택) {"묶음 이름": "이 묶음이 확인하는 것 한 줄"}. 적은 순서대로 보여 준다

기대값 (expect)
  "ALLOW"                                  결과 하나
  ["ALLOW", "TOOL_ERROR"]                  이 중 하나면 통과
  {"outcome": "POLICY_DENY", "policy": "정규식"}   거부한 정책 ID까지 확인
  {"D0": ..., "D1": ..., "*": ...}         Gateway마다 다르게. "*"는 나머지. 없는 Gateway는 기록만
  없음                                     기록만

자동 변수: {run} 시나리오마다 새 영문 16자, {ns} 영문 12자, {call} 호출마다 새 32자, {gateway} Gateway 이름
"""
from __future__ import annotations

import json
import os
import re
import secrets

from gateprobe.classify import DEFAULT_RULES, OUTCOMES, check_rules

AUTO_VARS = ("run", "ns", "call", "gateway")
_ALPHA = "abcdefghjkmnpqrstuvwxyz"
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.\-]*)\}")


def rid(n=16):
    """숫자 없는 무작위 ID (기록 안의 숫자 토큰과 섞이지 않게)."""
    return "".join(secrets.choice(_ALPHA) for _ in range(n))


def fill(value, variables):
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: str(variables[m.group(1)]) if m.group(1) in variables else m.group(0), value)
    if isinstance(value, dict):
        return {k: fill(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, variables) for v in value]
    return value


def unresolved(value):
    found = set()
    if isinstance(value, str):
        found |= set(_PLACEHOLDER.findall(value))
    elif isinstance(value, dict):
        for v in value.values():
            found |= unresolved(v)
    elif isinstance(value, list):
        for v in value:
            found |= unresolved(v)
    return found


def _env(value):
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise KeyError(f"환경 변수 {name}가 없음")
        return os.environ[name]
    return value


class Target:
    def __init__(self, data: dict, base_dir: str = "."):
        self.data = data
        self.name = data.get("name", "target")
        self.region = _env(data.get("region"))
        self.profile = _env(data.get("profile"))
        self.auth = data.get("auth") or {"type": "sigv4"}
        self.mcp_version = data.get("mcp_version")   # 없으면 client.MCP_VERSION
        self.classify = data.get("classify") or DEFAULT_RULES
        self.policy_id_pattern = data.get("policy_id_pattern")
        self.inject_args = data.get("inject_args") or {}
        self.fixture_profile = _env(data.get("fixture_profile")) or self.profile
        file_vars = {}
        self.vars_file_data = {}
        if data.get("vars_file"):
            path = data["vars_file"] if os.path.isabs(data["vars_file"]) else os.path.join(base_dir, data["vars_file"])
            self.vars_file_data = json.load(open(path, encoding="utf-8"))
            file_vars = {k: v for k, v in self.vars_file_data.items() if isinstance(v, str)}
        self.vars = {**file_vars, **{k: _env(v) for k, v in (data.get("vars") or {}).items()}}
        self.gateways_raw = data.get("gateways") or self.vars_file_data.get("gateways") or {}

    def gateway_url(self, name):
        return fill(_env(self.gateways_raw[name]), self.vars)

    @classmethod
    def load(cls, path):
        return cls(json.load(open(path, encoding="utf-8")), os.path.dirname(os.path.abspath(path)))


def tool_name(spec, tool):
    prefix = spec.get("target")
    return tool if (not prefix or "___" in tool) else f"{prefix}___{tool}"


def expectation(expect, gateway):
    """(허용 결과 집합, 정책 ID 정규식, 오류 정규식) 또는 None(기록만)."""
    if expect is None:
        return None
    if isinstance(expect, dict) and "outcome" not in expect:
        if gateway in expect:
            return expectation(expect[gateway], gateway)
        return expectation(expect.get("*"), gateway)
    if isinstance(expect, str):
        return {expect}, None, None
    if isinstance(expect, list):
        return set(expect), None, None
    outs = expect["outcome"]
    return ({outs} if isinstance(outs, str) else set(outs)), expect.get("policy"), expect.get("error")


def error_text(obs):
    """판정 불가의 원인을 기대값과 대조할 문자열: "HTTP상태 RPC코드 메시지 상세". 전송 시간 초과는 "None None ..."."""
    return f"{obs.get('http_status')} {obs.get('rpc_code')} {obs.get('rpc_message') or ''} {obs.get('detail') or ''}"


def matches(exp, outcome, policy_id, err_text=None):
    """UNKNOWN(판정 불가)을 기대할 때는 error 정규식이 있어야 하고, 관찰한 오류가 그 정규식과 맞아야 통과.
    그래야 의도한 검증 오류와 네트워크 시간 초과가 같은 통과로 섞이지 않는다."""
    if exp is None:
        return None
    allowed, policy, error = exp
    if outcome not in allowed:
        return False
    if policy and outcome == "POLICY_DENY":
        return bool(policy_id and re.search(policy, policy_id))
    if outcome == "UNKNOWN":
        return bool(error and err_text is not None and re.search(error, err_text))
    return True


def describe(exp):
    if exp is None:
        return "-"
    allowed, policy, error = exp
    s = "|".join(sorted(allowed))
    return s + (f" ({policy})" if policy else "") + (f" [오류 {error}]" if error else "")


def validate(spec: dict, target: Target | None = None, gateways=None) -> list:
    """오류 목록. 빈 목록이면 통과. AWS에 접속하지 않는다."""
    errors = []
    names = list(gateways or (target.gateways_raw.keys() if target else []))
    all_names = list(target.gateways_raw) if target else names   # 기대값의 Gateway 이름은 대상 전체와 비교
    known = set(AUTO_VARS) | (set(target.vars) if target else set())
    if target:
        errors += [f"대상 classify: {e}" for e in check_rules(target.classify)]
        if target.auth.get("type") not in ("sigv4", "bearer", "oauth"):
            errors.append(f"대상 auth.type 모름: {target.auth.get('type')}")
        if target.auth.get("type") == "bearer" and not target.auth.get("token_env"):
            errors.append("bearer 인증에는 token_env가 필요함")
        if target.auth.get("type") == "oauth" and not str(target.auth.get("token_url", "")).startswith("https://"):
            errors.append("oauth 인증에는 https://로 시작하는 token_url이 필요함")
        if target.auth.get("type") == "sigv4" and not target.region:
            errors.append("sigv4 인증에는 region이 필요함")
        from gateprobe.client import MCP_VERSIONS
        if target.mcp_version is not None and target.mcp_version not in MCP_VERSIONS:
            errors.append(f"대상 mcp_version 모름: {target.mcp_version} (쓸 수 있는 값: {', '.join(MCP_VERSIONS)})")
        if not names:
            errors.append("대상에 gateways가 없음")
        for n in names:
            raw = target.gateways_raw[n]
            if isinstance(raw, str) and not raw.startswith("env:"):
                url = fill(raw, target.vars)
                if unresolved(url) or not (url.startswith("https://") and url.rstrip("/").endswith("/mcp")):
                    errors.append(f"Gateway {n} URL 형식 오류")
        for k in unresolved(target.inject_args) - known:
            errors.append(f"inject_args의 변수 {{{k}}}를 채울 수 없음")
    if not spec.get("scenarios"):
        errors.append("scenarios가 비어 있음")
    for i, fx in enumerate(spec.get("fixtures", [])):
        if fx.get("type", "s3") != "s3":
            errors.append(f"fixtures[{i}] 지원하지 않는 형식: {fx.get('type')}")
        if not fx.get("bucket") or not fx.get("key") or ("body" not in fx and "body_file" not in fx):
            errors.append(f"fixtures[{i}]에 bucket, key, body(또는 body_file)가 필요함")
        if target:
            for k in unresolved({k: v for k, v in fx.items() if k != "body_file"}) - known:
                errors.append(f"fixtures[{i}]의 변수 {{{k}}}를 채울 수 없음")
    seen = set()
    if spec.get("scenarios") and not any(st.get("expect") is not None
                                         for sc in spec["scenarios"] for st in sc.get("steps", [])):
        errors.append("기대값(expect)이 있는 단계가 하나도 없음. 이대로 돌리면 아무것도 확인하지 않는다")
    for sc in spec.get("scenarios", []):
        sid = sc.get("id")
        if not sid or sid in seen:
            errors.append(f"시나리오 id가 없거나 중복: {sid}")
        seen.add(sid)
        todo = [k for k in ("제목", "요약", "분류") if "TODO" in str(sc.get(k, ""))]
        if todo:
            errors.append(f"{sid}: {', '.join(todo)}에 TODO가 남아 있음")
        if not sc.get("steps"):
            errors.append(f"{sid}: steps가 비어 있음")
        for j, st in enumerate(sc.get("steps", []), 1):
            where = f"{sid} {j}단계"
            if not st.get("tool"):
                errors.append(f"{where}: tool이 없음")
            left = [k for k in ("tool", "args", "expect") if "TODO" in json.dumps(st.get(k), ensure_ascii=False)]
            if left:   # gateprobe init이 남긴 자리. 채우기 전에는 실행하지 않는다
                errors.append(f"{where}: {', '.join(left)}에 TODO가 남아 있음")
                continue
            if target:
                for k in unresolved(st.get("args", {})) - known:
                    errors.append(f"{where}: 변수 {{{k}}}를 채울 수 없음")
            errors += [f"{where}: {e}" for e in _check_expect(st.get("expect"), all_names)]
            w = st.get("wait")
            if w is not None and not (isinstance(w, (int, float)) and not isinstance(w, bool) and 0 <= w <= 900):
                errors.append(f"{where}: wait는 0~900 사이의 초")
            ses = st.get("session")
            if ses is not None and not (
                    (isinstance(ses, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", ses))
                    or (isinstance(ses, dict) and (ses == {"omit": True} or set(ses) == {"raw"}))):
                errors.append(f"{where}: session은 이름, {{\"omit\": true}}, {{\"raw\": 값}} 중 하나")
    return errors


def _unknown_outcome(v):
    """기대값 오타에 가장 가까운 값을 제안한다 (검토 11-23). '결과'가 아니라 기대값(정상) 칸의 문제임을 밝힌다."""
    import difflib

    near = difflib.get_close_matches(str(v).upper(), OUTCOMES, n=1, cutoff=0.6)
    return (f"기대값(expect) {v!r}을 모른다." + (f" \"{near[0]}\"을 뜻하나요?" if near else "")
            + f" 쓸 수 있는 값: {', '.join(OUTCOMES)}")


def _check_expect(expect, names, nested=False, in_outcome=False):
    errs = []
    if expect is None or isinstance(expect, str) or isinstance(expect, list):
        values = [] if expect is None else ([expect] if isinstance(expect, str) else expect)
        errs += [_unknown_outcome(v) for v in values if v not in OUTCOMES]
        if "UNKNOWN" in values and not in_outcome:
            errs.append("UNKNOWN을 기대하려면 error 정규식이 필요: {\"outcome\": ..., \"error\": \"...\"} (의도한 오류와 시간 초과를 구분)")
        return errs
    if not isinstance(expect, dict):
        return [f"expect 형식 오류: {expect!r}"]
    if "outcome" in expect:
        errs += _check_expect(expect["outcome"], names, True, in_outcome=True)
        for key in ("policy", "error"):
            if expect.get(key):
                try:
                    re.compile(expect[key])
                except re.error as exc:
                    errs.append(f"{key} 정규식 오류: {exc}")
        outs = expect["outcome"] if isinstance(expect["outcome"], list) else [expect["outcome"]]
        if "UNKNOWN" in outs and not expect.get("error"):
            errs.append("UNKNOWN을 기대하려면 error 정규식이 필요 (의도한 오류와 시간 초과를 구분)")
        return errs
    if nested:
        return ["Gateway별 expect 안에 다시 Gateway별 expect를 쓸 수 없음"]
    for key, value in expect.items():
        if names and key != "*" and key not in names:
            errs.append(f"expect에 대상에 없는 Gateway 이름: {key}")
        errs += _check_expect(value, names, True)
    return errs
