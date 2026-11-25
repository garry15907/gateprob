"""AgentCore Gateway MCP 호출. 판정하지 않고 관찰한 그대로 돌려준다.

kind
  TOOL_RESULT      도구가 실행돼 결과를 돌려줌 (output: 구조화 결과, text: 텍스트 내용, is_error)
  RPC_ERROR        JSON-RPC 오류 (rpc_code, rpc_message, policy_id)
  TRANSPORT_ERROR  HTTP 오류, 시간 초과, 형식 오류, 응답 ID 불일치

인증
  {"type": "sigv4"}                          IAM 인증 Gateway. profile이 없으면 기본 자격 증명 체인 (CI의 OIDC 역할 등)
  {"type": "bearer", "token_env": "NAME"}    JWT 인증 Gateway. 토큰은 환경 변수에서만 읽는다
  {"type": "oauth", "token_url": "...", "client_id_env": "GW_CLIENT_ID", "client_secret_env": "GW_CLIENT_SECRET",
   "scope": "선택"}                          JWT 인증 Gateway. gateprobe가 client_credentials로 토큰을 받고 만료 전에 다시 받는다.
                                             클라이언트 ID와 비밀값은 환경 변수에서만 읽고 기록하지 않는다
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Gateway가 받는 MCP 버전은 Gateway 설정(protocolConfiguration.mcp.supportedVersions)마다 다르다.
# 받지 않는 버전을 보내면 HTTP 400 -32600 "Unsupported protocol version" (AWS 웹 검색 예제, 2026-11-23 실측).
# 2025-11-25 Gateway도 initialize 없이 바로 tools/list, tools/call을 받고 _meta가 있어도 된다(같은 날 실측).
MCP_VERSIONS = ("2026-07-28", "2025-11-25")   # 둘 다 받으면 앞쪽을 고른다
MCP_VERSION = MCP_VERSIONS[0]
SESSION_HEADER = "x-amzn-bedrock-agentcore-policy-session-id"


def meta(version: str) -> dict:
    """2026-07-28 판은 요청마다 _meta가 필요하다."""
    return {"io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {"name": "gateprobe", "version": "0.3"},
            "io.modelcontextprotocol/clientCapabilities": {}}


def version_hint(detail: str) -> Optional[str]:
    """버전 거부 응답이면 고칠 방법을 한 줄로."""
    if "Unsupported protocol version" not in (detail or ""):
        return None
    found = re.search(r'\\?"supported\\?"\s*:\s*\[([^\]]*)\]', detail)
    ok = re.sub(r'[\\"\s]', "", found.group(1)) if found else ""
    first = ok.split(",")[0] if ok else "<버전>"
    return f"이 Gateway가 받는 MCP 버전: {ok or '응답에 없음'}. 대상 파일에 \"mcp_version\": \"{first}\"을 적는다"


def auth_hint(status: Optional[int], detail: str, auth_type: str) -> Optional[str]:
    """Gateway 입구의 인증·권한 거부를 사람이 읽을 한 줄로 (11-23 외부 예제 A에서 401 -32001, README는 403 -32002)."""
    d = detail or ""
    if status == 401 or "-32001" in d or "Authentication error" in d:
        if auth_type == "sigv4":
            return ("Gateway가 인증을 거부했다(401). AWS 자격 증명이 만료됐거나, 세션 정책·권한 경계가 호출을 막고 있다. "
                    "aws login으로 다시 로그인하고, 쓰는 프로필이 맞는지 확인한다")
        return ("Gateway가 토큰을 거부했다(401). 토큰이 만료됐거나, 토큰을 받은 클라이언트가 Gateway의 허용 클라이언트"
                "(allowedClients)·범위에 없다. 클라이언트 ID와 비밀값, token_url을 확인한다")
    if status == 403 or "-32002" in d or "Authorization error" in d:
        return ("Gateway가 권한 부족으로 거부했다(403). 호출 신원에 bedrock-agentcore:InvokeGateway 권한(이 Gateway ARN)이 "
                "있어야 한다")
    if status == 404:
        return "Gateway 주소를 찾지 못했다(404). 대상 파일의 Gateway URL이 .../mcp로 끝나는지, Gateway가 지워지지 않았는지 확인한다"
    return None


def mask(text: str) -> str:
    """계정 ID처럼 보이는 12자리 숫자를 가린다 (기록을 공유할 수 있게)."""
    return re.sub(r"\d{12}", "<ACCOUNT>", text or "")


class OAuthToken:
    """client_credentials로 토큰을 받아 두고, 만료 60초 전부터는 새로 받는다. 값은 메모리에만 둔다."""

    def __init__(self, auth: dict, timeout: int = 30):
        self.url = auth["token_url"]
        self.scope = auth.get("scope") or ""
        self.id_env, self.secret_env = auth.get("client_id_env", "GW_CLIENT_ID"), auth.get("client_secret_env", "GW_CLIENT_SECRET")
        missing = [n for n in (self.id_env, self.secret_env) if not os.environ.get(n)]
        if missing:
            raise RuntimeError(f"환경 변수 {', '.join(missing)}가 비어 있다. 토큰을 받을 클라이언트 ID와 비밀값을 넣는다")
        self.timeout, self._token, self._until = timeout, None, 0.0

    def get(self) -> str:
        if self._token and time.time() < self._until - 60:
            return self._token
        cid, secret = os.environ[self.id_env].strip(), os.environ[self.secret_env].strip()
        form = {"grant_type": "client_credentials"}
        if self.scope:
            form["scope"] = self.scope
        basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
        req = Request(self.url, data=urlencode(form).encode(), method="POST",
                      headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basic})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read(65536))
        except HTTPError as exc:   # 응답 본문에 비밀값은 없지만 길게 남기지 않는다
            reason = exc.read(300).decode("utf-8", "replace")
            raise RuntimeError(f"토큰 발급 실패 (HTTP {exc.code}): {reason}. 클라이언트 ID·비밀값·token_url·scope를 확인한다") from None
        if not body.get("access_token"):
            raise RuntimeError("토큰 발급 응답에 access_token이 없다")
        self._token, self._until = body["access_token"], time.time() + float(body.get("expires_in", 3600))
        return self._token


class GatewayClient:
    def __init__(self, url: str, auth: Optional[dict] = None, region: Optional[str] = None,
                 profile: Optional[str] = None, timeout: int = 60, policy_id_pattern: Optional[str] = None,
                 mcp_version: Optional[str] = None):
        if not (url.startswith("https://") and url.rstrip("/").endswith("/mcp")):
            raise ValueError(f"https://.../mcp 형태의 Gateway URL이 필요함: {url[:60]}")
        self.mcp_version = mcp_version or MCP_VERSION
        if self.mcp_version not in MCP_VERSIONS:
            raise ValueError(f"모르는 MCP 버전: {self.mcp_version}. 쓸 수 있는 값: {', '.join(MCP_VERSIONS)}")
        self.url, self.region, self.timeout = url, region, timeout
        self.auth = auth or {"type": "sigv4"}
        self.policy_id = re.compile(policy_id_pattern or r"denied due to (?!policy evaluation)([A-Za-z0-9_\-]+)")
        self.credentials = None
        if self.auth["type"] == "sigv4":
            import boto3

            self.credentials = boto3.Session(profile_name=profile, region_name=region).get_credentials()
            if self.credentials is None:
                raise RuntimeError("AWS 자격 증명을 찾지 못함")
        elif self.auth["type"] == "bearer":
            if not os.environ.get(self.auth["token_env"]):
                raise RuntimeError(f"환경 변수 {self.auth['token_env']}에 토큰이 없음")
        elif self.auth["type"] == "oauth":
            self.oauth = OAuthToken(self.auth)
        else:
            raise ValueError(f"모르는 인증 방식: {self.auth['type']}")

    def _post(self, payload: dict, headers: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "MCP-Protocol-Version": self.mcp_version, **headers}
        if self.auth["type"] == "sigv4":
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest

            signed = AWSRequest(method="POST", url=self.url, headers=headers, data=body)
            SigV4Auth(self.credentials.get_frozen_credentials(), "bedrock-agentcore", self.region).add_auth(signed)
            headers = dict(signed.prepare().headers.items())
        elif self.auth["type"] == "oauth":
            headers["Authorization"] = "Bearer " + self.oauth.get()
        else:
            headers["Authorization"] = "Bearer " + os.environ[self.auth["token_env"]].strip()
        req = Request(self.url, data=body, method="POST", headers=headers)
        with urlopen(req, timeout=self.timeout) as resp:
            return resp.status, resp.read(1_048_577)

    def _rpc(self, method: str, params: dict, headers: dict) -> Dict[str, Any]:
        request_id = uuid.uuid4().hex
        params = {**params, "_meta": meta(self.mcp_version)}
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        obs: Dict[str, Any] = {"request_id": request_id}
        try:
            obs["http_status"], raw = self._post(payload, {"Mcp-Method": method, **headers})
        except HTTPError as exc:
            obs.update(kind="TRANSPORT_ERROR", http_status=exc.code, detail=mask(exc.read(4096).decode("utf-8", "replace"))[:600])
            hint = version_hint(obs["detail"]) or auth_hint(exc.code, obs["detail"], self.auth["type"])
            if hint:
                obs["hint"] = hint
            return obs
        except (URLError, TimeoutError, OSError) as exc:
            obs.update(kind="TRANSPORT_ERROR", http_status=None, detail=type(exc).__name__)
            return obs
        except RuntimeError as exc:   # 토큰 발급 실패 (OAuthToken)
            obs.update(kind="TRANSPORT_ERROR", http_status=None, detail=mask(str(exc))[:600], hint=str(exc)[:300])
            return obs
        try:
            parsed = json.loads(raw)
        except ValueError:
            obs.update(kind="TRANSPORT_ERROR", detail="INVALID_JSON")
            return obs
        if not isinstance(parsed, dict) or parsed.get("id") != request_id:
            obs.update(kind="TRANSPORT_ERROR", detail="RPC_ID_MISMATCH")
            return obs
        if isinstance(parsed.get("error"), dict):
            err = parsed["error"]
            message = mask(str(err.get("message", "")))
            found = self.policy_id.search(message)
            obs.update(kind="RPC_ERROR", rpc_code=err.get("code"), rpc_message=message[:600],
                       policy_id=found.group(1) if found else None)
            return obs
        obs.update(kind="RESULT", result=parsed.get("result") or {})
        return obs

    def call(self, tool: str, arguments: Dict[str, Any], session_id: Optional[str]) -> Dict[str, Any]:
        """session_id가 None이면 세션 헤더를 아예 보내지 않는다 (세션 헤더 시험용)."""
        headers = {"Mcp-Name": tool}
        if session_id is not None:
            headers[SESSION_HEADER] = session_id
        obs = self._rpc("tools/call", {"name": tool, "arguments": arguments}, headers)
        obs["tool"] = tool
        if obs.get("kind") == "RESULT":
            result = obs.pop("result")
            output, text = tool_output(result)
            obs.update(kind="TOOL_RESULT", is_error=bool(result.get("isError")), output=output, text=mask(text)[:2000])
        return obs

    def list_tools(self) -> Dict[str, Any]:
        tools, cursor = [], None
        while True:
            obs = self._rpc("tools/list", {"cursor": cursor} if cursor else {}, {})
            if obs.get("kind") != "RESULT":
                return obs
            tools += obs["result"].get("tools", [])
            cursor = obs["result"].get("nextCursor")
            if not cursor:
                return {"kind": "TOOLS", "tools": tools}


def tool_output(result: Dict[str, Any]):
    """(구조화 결과, 텍스트) 를 꺼낸다. 구조화 결과는 structuredContent, 없으면 텍스트를 JSON으로 읽어 본다."""
    texts = [item.get("text", "") for item in result.get("content", []) if isinstance(item, dict) and item.get("type") == "text"]
    text = "\n".join(texts)
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"], text
    for t in texts:
        try:
            value = json.loads(t)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value, text
    return {}, text
