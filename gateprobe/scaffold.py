"""gateprobe init: Gateway 정보를 읽어 대상 파일, 변수 파일, 시나리오 틀을 만든다.

만드는 것 (기본 폴더 checks/)
  target.json         대상 파일. Gateway 주소는 변수로만 적는다 (계정 ID가 저장소에 들어가지 않게)
  .gateprobe_vars.json  Gateway 주소, ARN, 정책 엔진 ID. git에 넣지 않는다 (.gitignore에 추가)
  scenarios.json      도구마다 시나리오 하나씩. 인자, 기대값, 제목은 TODO로 남긴다

기대값은 채우지 않는다. 무엇이 허용되고 막혀야 하는지는 정책을 만든 사람만 안다.
지금 결과를 그대로 기대값으로 적으면 잘못된 상태(예: 정책이 LOG_ONLY)까지 정답이 된다.
TODO가 남아 있으면 validate와 run이 실패한다.
"""
from __future__ import annotations

import json
import os
import re

TEMPLATE_HELP = (
    "gateprobe init이 만든 틀이다. TODO를 모두 채운 뒤 gateprobe validate로 확인한다. "
    "expect에 쓸 수 있는 값: \"ALLOW\", \"POLICY_DENY\", \"IAM_DENY\", \"TOOL_ERROR\", "
    "[\"IAM_DENY\", \"POLICY_DENY\"](어느 쪽으로 막혀도 됨). 같은 시나리오의 단계는 한 정책 세션으로 보낸다. "
    "제목, 요약, 분류는 보고서에 그대로 나온다."
)

GROUPS = {
    "유출 차단": "민감 데이터를 읽은 뒤 그 내용을 밖으로 보내면 막혀야 한다",
    "정상 업무": "막으면 안 되는 호출은 그대로 통과해야 한다",
    "기본 권한": "삭제처럼 위험한 호출은 막혀야 한다",
}


def find_gateway(control, ident):
    """ID, ARN, 이름 중 무엇으로든 Gateway를 찾는다."""
    if ident.startswith("arn:"):
        ident = ident.rsplit("/", 1)[-1]
    try:
        return control.get_gateway(gatewayIdentifier=ident)
    except Exception:   # 이름일 수 있다. 목록에서 찾는다
        pass
    token, found = None, []
    while True:
        resp = control.list_gateways(**({"nextToken": token} if token else {}))
        found += [g for g in resp.get("items", []) if g.get("name") == ident]
        token = resp.get("nextToken")
        if not token:
            break
    if len(found) != 1:
        raise LookupError(f"Gateway '{ident}'를 찾지 못했거나 같은 이름이 여러 개다 ({len(found)}개). ID로 지정할 것")
    return control.get_gateway(gatewayIdentifier=found[0]["gatewayId"])


def _prefix(tools):
    pre = {t["name"].split("___", 1)[0] for t in tools if "___" in t["name"]}
    return pre.pop() if len(pre) == 1 and all("___" in t["name"] for t in tools) else None


def _example(prop: dict):
    """도구 입력 스키마 한 칸에서 형식에 맞는 예시값. 정할 수 없으면 무엇을 넣을지 적은 TODO."""
    if "default" in prop:
        return prop["default"]
    if prop.get("enum"):
        return prop["enum"][0]
    if prop.get("examples"):
        return prop["examples"][0]
    if "example" in prop:
        return prop["example"]
    kind = prop.get("type")
    if kind in ("integer", "number"):
        return prop.get("minimum", 1)
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return {}
    desc = (prop.get("description") or prop.get("title") or "").strip().replace("\n", " ")
    return f"TODO: {desc[:60]}" if desc else "TODO"


def _args(tool):
    """필수 인자만 넣는다. 숫자·선택지·기본값이 있는 칸은 예시로 채우고, 문자열은 설명을 붙인 TODO로 남긴다."""
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    req = schema.get("required") or list(props)
    return {k: _example(props.get(k) or {}) for k in req}


def scenario_template(gw_name, tools):
    prefix = _prefix(tools)
    short = lambda n: n.split("___", 1)[1] if prefix else n
    scenarios = []
    for t in tools:
        sid = "normal_" + re.sub(r"[^A-Za-z0-9_]", "_", short(t["name"]))
        scenarios.append({"id": sid, "제목": "TODO 짧은 제목", "요약": "TODO 한 줄 설명", "분류": "정상 업무",
                          "설명": f"{short(t['name'])}: {(t.get('description') or '').strip()[:150]}",
                          "steps": [{"tool": short(t["name"]), "args": _args(t), "expect": "TODO"}]})
    scenarios.append({
        "id": "leak_after_sensitive_read", "제목": "TODO 짧은 제목", "요약": "TODO 한 줄 설명", "분류": "유출 차단",
        "설명": "민감 데이터를 읽는 도구와 밖으로 보내는 도구를 차례로 넣는다. 같은 시나리오는 한 정책 세션이라 "
                "'읽은 뒤 보내기 금지' 같은 순서 정책도 확인된다. 해당 도구가 없으면 이 시나리오를 지운다",
        "steps": [{"tool": "TODO 민감 데이터를 읽는 도구", "args": {}, "expect": "ALLOW"},
                  {"tool": "TODO 밖으로 보내는 도구", "args": {}, "expect": "TODO"}]})
    spec = {"name": f"{gw_name} 정책 점검", "설명": TEMPLATE_HELP, "분류": GROUPS, "scenarios": scenarios}
    if prefix:
        spec = {"name": spec["name"], "target": prefix, **{k: v for k, v in spec.items() if k != "name"}}
    return spec


def fetch_json(url, timeout=15):
    from urllib.request import urlopen

    with urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read(262144))


def token_url_from(gw, fetch=fetch_json):
    """JWT Gateway의 discoveryUrl(OIDC 설정)에서 토큰 주소를 찾는다. 못 찾으면 None."""
    jwt = (gw.get("authorizerConfiguration") or {}).get("customJWTAuthorizer") or {}
    url = jwt.get("discoveryUrl")
    if not url:
        return None, jwt
    try:
        return fetch(url).get("token_endpoint"), jwt
    except Exception:   # 네트워크·형식 문제면 수동 토큰(bearer)으로 물러난다
        return None, jwt


def init(gateway, region, profile=None, out_dir="checks", force=False, control=None, list_tools=None, log=print,
         fetch=fetch_json):
    """대상 파일, 변수 파일, 시나리오 틀을 쓴다. control, list_tools, fetch는 시험용으로 바꿔 끼울 수 있다."""
    if control is None:
        import boto3

        control = boto3.Session(profile_name=profile, region_name=region).client("bedrock-agentcore-control")
    gw = find_gateway(control, gateway)
    name = gw.get("name") or gw["gatewayId"]
    key = re.sub(r"[^A-Za-z0-9_-]", "_", name)
    pe = gw.get("policyEngineConfiguration") or {}
    auth_type = gw.get("authorizerType")

    warnings = []
    if auth_type == "AWS_IAM":
        auth = {"type": "sigv4"}
    elif auth_type == "CUSTOM_JWT":
        token_url, jwt = token_url_from(gw, fetch)
        if token_url:
            auth = {"type": "oauth", "token_url": token_url, "client_id_env": "GW_CLIENT_ID", "client_secret_env": "GW_CLIENT_SECRET"}
            n = len(jwt.get("allowedClients") or [])
            warnings.append("JWT 인증 Gateway다. gateprobe가 토큰을 직접 받는다. 실행 전에 환경 변수 GW_CLIENT_ID, GW_CLIENT_SECRET에 "
                            f"토큰을 받을 클라이언트의 ID와 비밀값을 넣는다(이 Gateway가 허용하는 클라이언트 {n}개 중 하나)")
        else:
            auth = {"type": "bearer", "token_env": "GW_TOKEN"}
            warnings.append("JWT 인증 Gateway인데 토큰 주소를 찾지 못했다. 실행 전에 환경 변수 GW_TOKEN에 토큰을 직접 넣는다")
    else:
        raise ValueError(f"지원하지 않는 Gateway 인증 방식: {auth_type}. gateprobe는 AWS_IAM(SigV4)과 CUSTOM_JWT만 지원한다")
    if not pe.get("arn"):
        warnings.append("이 Gateway에는 정책 엔진이 없다. IAM과 도구 동작만 점검된다")
    elif pe.get("mode") != "ENFORCE":
        warnings.append(f"정책 엔진 모드가 {pe.get('mode')}다. ENFORCE가 아니면 정책이 기록만 하고 막지 않는다. "
                        "이 상태의 결과를 기대값으로 적지 말 것")
    else:   # 11-23 외부 예제 B: 허용 정책이 없는 도구 4개가 tools/list에서 빠졌다
        warnings.append("정책 엔진이 ENFORCE면 도구 목록에 지금 허용된 도구만 보일 수 있다. 막혀야 할 도구(예: 송금, 삭제)는 "
                        "틀에 없을 수 있으니 이름을 확인해 직접 시나리오에 넣는다")

    # Gateway가 받는 MCP 버전 중 gateprobe가 아는 것을 고른다. 설정에 목록이 없으면 기본값을 쓴다
    from gateprobe.client import MCP_VERSIONS
    supported = ((gw.get("protocolConfiguration") or {}).get("mcp") or {}).get("supportedVersions") or []
    mcp_version = next((v for v in MCP_VERSIONS if v in supported), None)
    if supported and mcp_version is None:
        warnings.append(f"Gateway가 받는 MCP 버전({', '.join(supported)}) 중 gateprobe가 아는 것이 없다 "
                        f"(gateprobe: {', '.join(MCP_VERSIONS)}). 호출이 거부될 것이다")

    vars_ = {"gateway_url": gw["gatewayUrl"], "gateway_arn": gw["gatewayArn"]}
    if pe.get("arn"):
        vars_.update(policy_engine_id=pe["arn"].rsplit("/", 1)[-1], policy_engine_mode=pe.get("mode") or "")
    # 프로필 이름은 대상 파일에 적지 않는다. 내 PC의 설정일 뿐이고, 저장소에 올려 CI에서 쓰면 그 프로필이 없어 실패한다.
    # 로컬에서는 run에 --profile을 붙인다 (다음 단계 안내에 넣음)
    target = {"name": name, "region": region, "auth": auth,
              "vars_file": ".gateprobe_vars.json", "gateways": {key: "{gateway_url}"}, "labels": {key: name},
              "tool_labels": {}}
    if mcp_version:
        target["mcp_version"] = mcp_version

    if list_tools is None:
        from gateprobe.client import GatewayClient

        list_tools = GatewayClient(gw["gatewayUrl"], auth, region, profile, mcp_version=mcp_version).list_tools
    got = list_tools()
    if got.get("kind") != "TOOLS":
        raise RuntimeError("도구 목록을 읽지 못했다: " + json.dumps(got, ensure_ascii=False)[:300]
                           + (f"\n안내: {got['hint']}" if got.get("hint") else ""))
    tools = got["tools"]
    if not tools:
        warnings.append("도구 목록이 비어 있다. 정책이 목록 조회까지 거르는지 확인할 것")
    spec = scenario_template(name, tools)

    os.makedirs(out_dir, exist_ok=True)
    files = {"target.json": target, ".gateprobe_vars.json": vars_, "scenarios.json": spec}
    exists = [f for f in files if os.path.exists(os.path.join(out_dir, f))]
    if exists and not force:
        raise FileExistsError(f"이미 있는 파일: {', '.join(exists)} ({out_dir}). 덮어쓰려면 --force")
    for fn, data in files.items():
        with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
    # 계정 정보 파일과 observe 초안(지금 결과가 적힌 한때의 기록)은 저장소에 넣지 않는다
    gi = ".gitignore"
    have = open(gi, encoding="utf-8").read().splitlines() if os.path.exists(gi) else []
    add = [line for line, short in ((os.path.join(out_dir, ".gateprobe_vars.json").replace("\\", "/"), ".gateprobe_vars.json"),
                                    (os.path.join(out_dir, "*_observed.json").replace("\\", "/"), "*_observed.json"))
           if line not in have and short not in have]
    if add:
        with open(gi, "a", encoding="utf-8") as f:
            f.write(("\n" if have and have[-1] else "") + "\n".join(add) + "\n")

    log(f"Gateway: {name} ({auth_type}) / 정책 엔진: {pe.get('mode') or '없음'} / 도구 {len(tools)}개"
        f" / MCP {mcp_version or '설정에 없음, 기본값 사용'}")
    for w in warnings:
        log("주의: " + w)
    arg_todo = sum(1 for sc in spec["scenarios"] for st in sc["steps"] for v in st["args"].values()
                   if isinstance(v, str) and v.startswith("TODO"))
    arg_all = sum(len(st["args"]) for sc in spec["scenarios"] for st in sc["steps"])
    log(f"만듦: {out_dir}/target.json, {out_dir}/scenarios.json, {out_dir}/.gateprobe_vars.json (git 제외)")
    log(f"인자 {arg_all}칸 중 {arg_all - arg_todo}칸은 도구 설명으로 예시를 채웠고 {arg_todo}칸이 TODO로 남았다")
    prof = f" --profile {profile}" if profile else ""
    s, t = f"{out_dir}/scenarios.json", f"{out_dir}/target.json"
    obs = s[:-len(".json")] + "_observed.json"
    log("다음 단계 (README 3절과 같은 번호)")
    if auth.get("type") == "oauth":
        log("  0. 토큰을 받을 클라이언트 정보를 넣는다: 환경 변수 GW_CLIENT_ID, GW_CLIENT_SECRET")
    log(f"  2. gateprobe doctor --target {t}{prof}   (접속·인증·버전·정책 엔진 모드 진단)")
    log(f"  3. {s}의 인자 TODO를 채운다. 필요 없는 시나리오는 지운다")
    log(f"  4. (선택) gateprobe observe --spec {s} --target {t}{prof} --execute   → {obs}에 지금 결과가 적힌다. 시험용 Gateway에서만")
    log(f"  5. 정상(expect) TODO를 정한다: gateprobe ui --spec {s} --draft {obs} --target {t}   (화면에서 고름. 파일에서 직접 고쳐도 된다)")
    log(f"     그다음 형식 검사: gateprobe validate --spec {s} --target {t}")
    log(f"  6. gateprobe run --spec {s} --target {t}{prof} --execute --html report.html")
    return {"gateway": name, "warnings": warnings, "tools": [t["name"] for t in tools]}
