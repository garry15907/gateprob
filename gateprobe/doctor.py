"""gateprobe doctor: 점검을 돌리기 전에 막힐 곳을 한 번에 확인하고, 문제마다 고치는 법을 한 줄로 알려 준다.

확인하는 것
  1. 대상 파일 형식
  2. 자격 증명: SigV4면 AWS 신원, oauth면 토큰 발급, bearer면 환경 변수
  3. Gateway마다 도구 목록 읽기 (MCP 버전, 입구 인증·권한, 주소 문제를 여기서 잡는다)
  4. (AWS 자격 증명이 있으면) Gateway 설정: 정책 엔진 모드, 받는 MCP 버전과 대상 파일의 mcp_version
결과 줄: [통과] / [주의] / [실패]. 실패가 하나라도 있으면 종료 코드 2.
"""
from __future__ import annotations

from urllib.parse import urlparse

from gateprobe.client import MCP_VERSION, OAuthToken, mask
from gateprobe.spec import validate


def gateway_id_from_url(url: str):
    """https://<gatewayId>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp 에서 gatewayId."""
    host = urlparse(url).hostname or ""
    return host.split(".")[0] if ".gateway.bedrock-agentcore." in host else None


def run_doctor(target, gateways, make_client, aws_identity=None, control=None, log=print):
    """make_client(gw) -> GatewayClient, aws_identity() -> 신원 ARN 문자열, control -> bedrock-agentcore-control 클라이언트.
    시험할 때는 가짜를 넣는다. 마지막 줄에 실패·주의 개수와 정책 엔진 모드를 적는다(외부 검토 11-23: 주의만 있어도
    '문제 없음'으로 끝나 LOG_ONLY를 놓칠 수 있었다). 반환: 실패 수."""
    st = {"실패": 0, "주의": 0, "modes": {}}

    def say(kind, msg, fix=None):
        st[kind] = st.get(kind, 0) + 1
        log(f"[{kind}] {msg}" + (f"\n       → {fix}" if fix else ""))

    _checks(target, gateways, make_client, aws_identity, control, say, st["modes"])
    modes = ", ".join(f"{g} {m}" for g, m in st["modes"].items()) or "확인 못 함"
    if not st["실패"] and not st["주의"]:
        log(f"진단 끝: 문제 없음 (정책 엔진: {modes})")
    else:
        log(f"진단 끝: 실패 {st['실패']}개, 주의 {st['주의']}개 (정책 엔진: {modes}). "
            + ("[실패]의 → 줄대로 고친 뒤 다시 실행한다" if st["실패"] else "[주의]를 읽고 점검을 계속할지 정한다"))
    return st["실패"]


def _checks(target, gateways, make_client, aws_identity, control, say, modes):
    fails = 0   # 아래 이른 return은 '이 뒤는 같은 이유로 실패'라서 멈추는 것

    # 1. 대상 파일
    dummy = {"scenarios": [{"id": "_", "steps": [{"tool": "_", "args": {}, "expect": "ALLOW"}]}]}
    errs = validate(dummy, target, gateways)
    if errs:
        for e in errs:
            say("실패", f"대상 파일: {e}", "대상 파일(target.json)을 고친다. gateprobe init으로 다시 만들어도 된다")
    else:
        say("통과", f"대상 파일 형식 (Gateway {len(gateways)}개, 인증 {target.auth.get('type')}, MCP {target.mcp_version or MCP_VERSION})")

    # 2. 자격 증명
    kind = target.auth.get("type")
    if kind == "sigv4":
        try:
            say("통과", f"AWS 신원: {mask(aws_identity())}")
        except Exception as exc:
            why = str(exc).strip().splitlines()[-1][:200]
            fix = ("--no-deps 없이 다시 설치한다: pip install gateprobe-<버전>-py3-none-any.whl" if "boto3" in why
                   else "aws login(또는 aws sso login)으로 로그인하고, --profile이 맞는지 확인한다")
            say("실패", f"AWS 자격 증명을 쓸 수 없다: {why}", fix)
            return fails   # 이 뒤는 모두 같은 이유로 실패한다
    elif kind == "oauth":
        try:
            OAuthToken(target.auth).get()
            say("통과", "토큰 발급 (token_url, 클라이언트 ID·비밀값)")
        except Exception as exc:
            say("실패", str(exc)[:300], "환경 변수 GW_CLIENT_ID, GW_CLIENT_SECRET(또는 대상 파일에 적은 이름)를 확인한다")
            return fails
    elif kind == "bearer":
        import os
        if os.environ.get(target.auth.get("token_env", "")):
            say("통과", f"토큰 환경 변수 {target.auth['token_env']} 있음 (유효한지는 3번에서 확인)")
        else:
            say("실패", f"환경 변수 {target.auth.get('token_env')}가 비어 있다", "토큰을 받아 넣거나, 대상 파일 인증을 oauth로 바꿔 gateprobe가 받게 한다")
            return fails

    # 3. Gateway마다 도구 목록
    for gw in gateways:
        try:
            got = make_client(gw).list_tools()
        except Exception as exc:
            say("실패", f"{gw}: 접속 준비 실패 - {str(exc)[:200]}")
            continue
        if got.get("kind") == "TOOLS":
            names = [t.get("name", "") for t in got["tools"]]
            if names:
                say("통과", f"{gw}: 도구 {len(names)}개 ({', '.join(names[:4])}{' 등' if len(names) > 4 else ''})")
            else:
                say("주의", f"{gw}: 도구 목록이 비어 있다", "정책 엔진이 목록 조회까지 거르는지, 대상(target)이 READY인지 확인한다")
        else:
            detail = got.get("detail") or got.get("rpc_message") or ""
            say("실패", f"{gw}: 도구 목록을 읽지 못함 (HTTP {got.get('http_status')}) {detail[:160]}",
                got.get("hint") or "Gateway URL과 네트워크를 확인한다")

    # 4. Gateway 설정 (제어 영역. 권한이 없으면 건너뛴다)
    if control is None:
        return fails
    for gw in gateways:
        gid = gateway_id_from_url(target.gateway_url(gw))
        if not gid:
            continue
        try:
            conf = control.get_gateway(gatewayIdentifier=gid)
        except Exception as exc:
            say("주의", f"{gw}: Gateway 설정을 읽지 못해 정책 엔진 상태는 확인하지 않음 ({type(exc).__name__})")
            modes[gw] = "확인 못 함"
            continue
        pe = conf.get("policyEngineConfiguration") or {}
        if not pe.get("arn"):
            modes[gw] = "없음"
            say("주의", f"{gw}: 정책 엔진이 없다. 정책 차단은 나오지 않고 IAM과 도구 동작만 점검된다")
        elif pe.get("mode") != "ENFORCE":
            modes[gw] = f"{pe.get('mode')}(막지 않음)"
            say("주의", f"{gw}: 정책 엔진 모드가 {pe.get('mode')}다. 정책이 기록만 하고 막지 않는다",
                "이 상태의 결과를 정상값으로 적지 않는다. 운영과 같은 모드인지 확인한다")
        else:
            modes[gw] = "ENFORCE"
            say("통과", f"{gw}: 정책 엔진 ENFORCE")
        supported = ((conf.get("protocolConfiguration") or {}).get("mcp") or {}).get("supportedVersions") or []
        mine = target.mcp_version or MCP_VERSION
        if supported and mine not in supported:
            say("실패", f"{gw}: Gateway가 받는 MCP 버전 {supported}에 대상 파일의 {mine}이 없다",
                f"대상 파일에 \"mcp_version\": \"{supported[0]}\"을 적는다")
    return fails
