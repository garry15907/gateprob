"""gateprobe 테스트 (AWS 없이 가짜 Gateway). defense-eval 폴더에서 python -m gateprobe.test_gateprobe"""
import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET

from gateprobe import report, runner
from gateprobe.classify import DEFAULT_RULES, check_rules, classify
from gateprobe.spec import Target, expectation, fill, matches, tool_name, unresolved, validate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# T01 스택의 분류 규칙. 패키지만 설치한 곳에서도 돌도록 사본을 둔다 (프로젝트 폴더가 있으면 원본과 같은지 확인)
PROJECT = {"policy_deny_codes": [-20001], "rules": [{"when": {"is_error": True}, "then": "UNKNOWN"},
           {"when": {"path": "ok", "equals": True}, "then": "ALLOW"},
           {"when": {"path": "status", "equals": "ACCESS_DENIED"}, "then": "IAM_DENY"}], "default": "TOOL_ERROR"}
_proj = os.path.join(ROOT, "traces", "target_defense_eval.json")
if os.path.exists(_proj):
    assert json.load(open(_proj, encoding="utf-8"))["classify"] == PROJECT, "분류 규칙 사본이 원본과 다름"


def res(output=None, text="", is_error=False):
    return {"kind": "TOOL_RESULT", "output": output or {}, "text": text, "is_error": is_error}


def deny(pid="p1"):
    return {"kind": "RPC_ERROR", "rpc_code": -20001, "policy_id": pid}


class FakeGateway:
    """규칙표대로 답한다: {(gateway, tool): 관찰}. 세션과 인자를 기록한다."""

    def __init__(self, gw, table, log):
        self.gw, self.table, self.log = gw, table, log

    def call(self, tool, args, session_id):
        self.log.append((self.gw, tool, dict(args), session_id))
        return self.table.get((self.gw, tool), res({"ok": True}))


def make_target(**kw):
    data = {"name": "t", "region": "r", "gateways": {"A": "https://a/mcp", "B": "https://b/mcp"}, "vars": {"bucket": "BK"}}
    data.update(kw)
    return Target(data)


def run_tests():
    n = 0
    # 분류: 프로젝트 규칙은 예전 trace_check와 같게
    assert classify(deny(), PROJECT) == "POLICY_DENY"
    assert classify({"kind": "RPC_ERROR", "rpc_code": -32602}, PROJECT) == "UNKNOWN"
    assert classify({"kind": "TRANSPORT_ERROR"}, PROJECT) == "UNKNOWN"
    assert classify(res({"ok": True}), PROJECT) == "ALLOW"
    assert classify(res({"ok": False, "status": "ACCESS_DENIED"}), PROJECT) == "IAM_DENY"
    assert classify(res({"ok": False, "status": "NOT_FOUND"}), PROJECT) == "TOOL_ERROR"
    assert classify(res({"ok": True}, is_error=True), PROJECT) == "UNKNOWN"; n += 1
    # 기본 규칙: 응답 형식을 모르는 도구
    assert classify(res(text="An error occurred (AccessDenied) when calling GetObject"), DEFAULT_RULES) == "IAM_DENY"
    assert classify(res(text="boom", is_error=True), DEFAULT_RULES) == "TOOL_ERROR"
    assert classify(res(text="An internal error occurred. Please retry later.", is_error=True), DEFAULT_RULES) == "UNKNOWN"
    assert classify(res(text="hello"), DEFAULT_RULES) == "ALLOW"; n += 1
    # 규칙 조건: 경로, in, matches, exists, 여러 조건
    rules = {"rules": [{"when": [{"path": "r.code", "in": [403, 401]}, {"is_error": True}], "then": "IAM_DENY"},
                       {"when": {"path": "items.0.id", "matches": "^x"}, "then": "ALLOW"},
                       {"when": {"path": "warn", "exists": True}, "then": "TOOL_ERROR"}], "default": "UNKNOWN"}
    assert check_rules(rules) == []
    assert classify(res({"r": {"code": 403}}, is_error=True), rules) == "IAM_DENY"
    assert classify(res({"r": {"code": 403}}), rules) == "UNKNOWN"
    assert classify(res({"items": [{"id": "x1"}]}), rules) == "ALLOW"
    assert classify(res({"warn": None}), rules) == "TOOL_ERROR"; n += 1
    bad = {"rules": [{"when": {"equals": 1}, "then": "ALLOW"}, {"when": {"text_matches": "("}, "then": "NOPE"}], "default": "X"}
    assert len(check_rules(bad)) == 4; n += 1
    # 기대값 형식
    assert expectation("ALLOW", "A") == ({"ALLOW"}, None, None)
    assert expectation({"A": "ALLOW", "*": "IAM_DENY"}, "B") == ({"IAM_DENY"}, None, None)
    assert expectation({"A": "ALLOW"}, "B") is None
    e = expectation({"outcome": "POLICY_DENY", "policy": "^temporal"}, "A")
    assert matches(e, "POLICY_DENY", "temporal_x") and not matches(e, "POLICY_DENY", "cedar_y") and not matches(e, "POLICY_DENY", None)
    assert matches(expectation(["ALLOW", "TOOL_ERROR"], "A"), "TOOL_ERROR", None); n += 1
    # 판정 불가 기대: 오류 정규식이 맞아야 통과. 시간 초과는 통과가 아님. 정규식 없는 UNKNOWN 기대는 형식 오류
    from gateprobe.spec import error_text
    eu = expectation({"outcome": "UNKNOWN", "error": r"^400 "}, "A")
    assert matches(eu, "UNKNOWN", None, error_text({"http_status": 400, "detail": "ValidationException"}))
    assert not matches(eu, "UNKNOWN", None, error_text({"http_status": None, "detail": "TimeoutError"}))
    assert not matches(expectation(["UNKNOWN"], "A"), "UNKNOWN", None, "400 x")
    assert any("error 정규식" in e for e in validate({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": "UNKNOWN"}]}]}, None, []))
    assert any("error 정규식" in e for e in validate({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": {"outcome": "UNKNOWN"}}]}]}, None, []))
    assert validate({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": {"outcome": "UNKNOWN", "error": "^400"}}]}]}, None, []) == []; n += 1
    # 변수와 도구 이름
    assert fill({"k": ["{bucket}/{x}"]}, {"bucket": "B"}) == {"k": ["B/{x}"]} and unresolved({"k": "{x}"}) == {"x"}
    assert tool_name({"target": "tt"}, "read") == "tt___read" and tool_name({"target": "tt"}, "o___read") == "o___read"
    assert tool_name({}, "read") == "read"; n += 1
    # 형식 검사
    spec = {"scenarios": [{"id": "s", "steps": [{"tool": "x", "args": {"b": "{bucket}", "c": "{nope}"},
                                                 "expect": {"A": "ALLOW", "C": "OOPS"}}]}],
            "fixtures": [{"bucket": "{bucket}", "key": "k"}]}
    errs = validate(spec, make_target(), ["A", "B"])
    assert any("nope" in e for e in errs) and any("C" in e for e in errs) and any("OOPS" in e for e in errs)
    assert any("body" in e for e in errs), errs
    assert validate({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": "ALLOW"}]}]}, make_target(), ["A"]) == []
    assert validate({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": {"A": "ALLOW", "B": "IAM_DENY"}}]}]}, make_target(), ["A"]) == []
    assert validate({"scenarios": [{"id": "s", "steps": [{"tool": "x"}]}]}, make_target(gateways={"A": "http://a"}), ["A"]); n += 1
    # 환경 변수 Gateway URL
    os.environ["GWCHECK_TEST_URL"] = "https://env/mcp"
    assert make_target(gateways={"A": "env:GWCHECK_TEST_URL"}).gateway_url("A") == "https://env/mcp"; n += 1
    # 실행: 한 시나리오는 한 세션, inject_args, 사전 객체, 회귀와 판정 불가 구분
    spec = {"name": "demo", "target": "tt",
            "fixtures": [{"bucket": "{bucket}", "key": "in/{run}.txt", "body": "x {run}"}],
            "scenarios": [{"id": "s1", "steps": [{"tool": "read", "expect": "ALLOW"},
                                                 {"tool": "send", "expect": {"A": "ALLOW", "B": {"outcome": "POLICY_DENY", "policy": "^tp"}}}]},
                          {"id": "s2", "steps": [{"tool": "del", "args": {"k": "{bucket}"}, "expect": "IAM_DENY"}]}]}
    target = make_target(inject_args={"run_id": "{run}"})
    log, puts = [], []
    table = {("B", "tt___send"): deny("tp_1"), ("A", "tt___del"): res({}, "AccessDenied"), ("B", "tt___del"): res({}, "AccessDenied")}
    rec = runner.run(spec, target, ["A", "B"], lambda g: FakeGateway(g, table, log), lambda b, k, body: puts.append((b, k, body)), log=lambda m: None)
    assert rec["summary"] == {"calls": 6, "checked": 6, "passed": 6, "regressions": 0, "unknown": 0, "fixture_errors": 0}, rec["summary"]
    assert runner.exit_code(rec["summary"]) == 0
    sessions = {}
    for gw, tool, args, sid in log:
        assert "run_id" in args
        sessions.setdefault((gw, args["run_id"]), set()).add(sid)
    assert all(len(v) == 1 for v in sessions.values()) and len(sessions) == 4
    assert len(puts) == 4 and puts[0][0] == "BK" and puts[0][1].endswith(".txt") and "{run}" not in puts[0][2]
    assert log[2][2]["k"] == "BK"; n += 1
    # 회귀: B가 정책 거부 대신 허용, 판정 불가: A 전송 오류
    table2 = {("A", "tt___read"): {"kind": "TRANSPORT_ERROR"}, ("A", "tt___del"): res({}, "AccessDenied"), ("B", "tt___del"): res({}, "AccessDenied")}
    rec = runner.run(spec, target, ["A", "B"], lambda g: FakeGateway(g, table2, []), lambda *x: None, log=lambda m: None)
    assert rec["summary"]["regressions"] == 1 and rec["summary"]["unknown"] == 1 and runner.exit_code(rec["summary"]) == 1
    rec_u = runner.run(spec, target, ["A"], lambda g: FakeGateway(g, table2, []), lambda *x: None, log=lambda m: None)
    assert runner.exit_code(rec_u["summary"]) == 2; n += 1
    # 정책 ID가 기대와 다르면 회귀
    table3 = {**table, ("B", "tt___send"): deny("cedar_9")}
    rec3 = runner.run(spec, target, ["B"], lambda g: FakeGateway(g, table3, []), lambda *x: None, log=lambda m: None)
    assert rec3["summary"]["regressions"] == 1; n += 1
    # 사전 객체 실패: 그 시나리오는 호출하지 않고 판정 불가
    def boom(*x):
        raise RuntimeError("no bucket")
    calls = []
    rec4 = runner.run(spec, target, ["A"], lambda g: FakeGateway(g, table, calls), boom, log=lambda m: None)
    assert rec4["summary"]["fixture_errors"] == 2 and calls == [] and runner.exit_code(rec4["summary"]) == 2; n += 1
    # 보고서: JUnit은 올바른 XML, 실패와 오류 수
    x = ET.fromstring(report.junit(rec).encode("utf-8"))
    suites = {s.get("name"): s for s in x}
    assert suites["A"].get("errors") == "1" and suites["B"].get("failures") == "1"
    md = report.markdown(rec)
    assert "불일치" in md and "확인 필요" in md and "| s1 |" in md; n += 1
    md = report.markdown(rec, None, {"s1": {"제목": "민감 내용 발송", "요약": "읽고 보냄", "분류": "유출 차단"}})
    assert "| 유출 차단" in md and "민감 내용 발송<br><sub>읽고 보냄</sub>" in md
    # 프로젝트 시나리오 파일과 대상 파일이 형식 검사를 통과 (참조 파일이 있을 때만)
    tpath = os.path.join(ROOT, "traces", "target_defense_eval.json")
    if os.path.exists(os.path.join(ROOT, "live_evidence", "private_t01_refs.json")):
        t = Target.load(tpath)
        assert validate(json.load(open(os.path.join(ROOT, "traces", "t01_t02.json"), encoding="utf-8")), t, list(t.gateways_raw)) == []
        n += 1
    # 단계별 세션: 이름마다 새 세션, 헤더 생략은 None, raw는 그대로, 형식 검사
    spec_s = {"scenarios": [{"id": "ss", "steps": [
        {"tool": "read", "expect": "ALLOW"}, {"tool": "send", "session": "B", "expect": "ALLOW"},
        {"tool": "send", "expect": "ALLOW"}, {"tool": "send", "session": {"omit": True}, "expect": "ALLOW"},
        {"tool": "send", "session": {"raw": ""}, "expect": "ALLOW"}]}]}
    log_s = []
    rec_s = runner.run(spec_s, make_target(), ["A"], lambda g: FakeGateway(g, {}, log_s), lambda *x: None, log=lambda m: None)
    sids = [x[3] for x in log_s]
    assert sids[0] == sids[2] and sids[1] not in (sids[0], None) and sids[3] is None and sids[4] == ""
    assert [r["session"] for r in rec_s["configs"]["A"]][:2] == ["main", "B"]
    bad = {"scenarios": [{"id": "s", "steps": [{"tool": "x", "session": {"omit": False}}, {"tool": "x", "session": "1bad"}]}]}
    assert sum("session" in e for e in validate(bad, None, [])) == 2; n += 1
    # CLI 형식 검사 명령
    from gateprobe.__main__ import main
    with tempfile.TemporaryDirectory() as d:
        sp, tp = os.path.join(d, "s.json"), os.path.join(d, "t.json")
        json.dump({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": "ALLOW"}]}]}, open(sp, "w"))
        json.dump({"region": "r", "gateways": {"A": "https://a/mcp"}}, open(tp, "w"))
        assert main(["validate", "--spec", sp, "--target", tp]) == 0
        json.dump({"scenarios": [{"id": "s", "steps": [{"tool": "x", "expect": "ALOW"}]}]}, open(sp, "w"))
        assert main(["validate", "--spec", sp, "--target", tp]) == 3
        assert main(["run", "--spec", sp, "--target", tp]) == 3
    n += 1
    # HTML 보고서: 기대와 다른 호출을 위로 올리고, 연속된 같은 결과를 묶고, 계정 ID를 가린다
    from gateprobe import html_report
    row = lambda st, tool, exp, obs, m, msg=None: {"scenario": "s", "step": st, "tool": tool, "session": "main", "expected": exp,
                                                   "observed": obs, "match": m, "rpc_message": msg, "http_status": 200}
    rec = {"spec": "x", "target": "y", "created_utc": "2026-11-19T00:00:00", "configs": {"A": [
        row(1, "read_file", None, "ALLOW", None), row(2, "publish_notice", "POLICY_DENY", "POLICY_DENY", True),
        row(3, "publish_notice", "POLICY_DENY", "POLICY_DENY", True),
        row(4, "publish_notice", "POLICY_DENY", "ALLOW", False, "arn:aws:iam::123456789012:role/x")]},
        "summary": {"calls": 4, "checked": 3, "passed": 2, "regressions": 1, "unknown": 0, "fixture_errors": 0}}
    h = html_report.render(rec, None, {"s": {"제목": "민감 내용 발송", "요약": "읽고 보냄", "분류": "유출 차단"}},
                           {"publish_notice": "공지"}, {"유출 차단": "막혀야 한다"})
    assert "종합 판정: <b>부적합</b>" in h and "123456789012" not in h and "&lt;ACCOUNT&gt;" in h
    assert "공지 정책 거부 ×2" in h and "민감 내용 발송" in h and ">불일치<" in h and "3. 불일치 호출 상세" in h
    assert "차단돼야 할 호출이 허용됨" in h and "양호" not in h and "취약" not in h
    h = html_report.render(rec, None, {"s": "S1. 보고서 읽고 공지(테스트). 둘째 문장"})   # 제목이 없는 예전 시나리오 파일
    assert "보고서 읽고 공지<" in h; n += 1

    # 거짓 통과 막기 (11-20 외부 검토): 종료 코드, HTML, 작업 요약, JUnit이 같은 판단을 해야 한다
    def case(rows, summary):
        r = {"spec": "x", "target": "y", "created_utc": "2026-11-20T00:00:00", "configs": {"A": rows}, "summary": summary}
        x = ET.fromstring(report.junit(r).encode("utf-8"))[0]
        return runner.exit_code(summary), html_report.render(r), report.markdown(r), x
    summ = lambda **k: {"calls": 0, "checked": 0, "passed": 0, "regressions": 0, "unknown": 0, "fixture_errors": 0, **k}
    # 1) 사전 준비 실패만 있고 호출 0건
    code, h, md, x = case([{"scenario": "s", "step": 0, "tool": "(fixtures)", "expected": None, "observed": "UNKNOWN",
                            "match": None, "error": "NoSuchBucket"}], summ(fixture_errors=1))
    assert code == 2 and "종합 판정: <b>점검 미완료</b>" in h and "점검 미완료" in md.splitlines()[0]
    assert "NoSuchBucket" in h and x.get("errors") == "1"; n += 1
    # 2) 기대값이 하나도 없는 실행 (TODO 템플릿을 그대로 돌린 경우)
    code, h, md, x = case([row(1, "read_file", None, "ALLOW", None)], summ(calls=1))
    assert code == 2 and "종합 판정: <b>점검 미완료</b>" in h and "점검 미완료" in md.splitlines()[0]; n += 1
    # 3) 같은 시나리오에서 판정 불가가 먼저, 확정 회귀가 나중: 회귀가 가려지면 안 된다
    code, h, md, x = case([row(1, "read_file", "ALLOW", "UNKNOWN", False), row(2, "publish_notice", "POLICY_DENY", "ALLOW", False)],
                          summ(calls=2, checked=2, regressions=1, unknown=1))
    assert code == 1 and "종합 판정: <b>부적합</b>" in h and ">불일치<" in h and md.splitlines()[0] == "### 종합 판정: 부적합 (불일치 1건)"
    # 터미널·HTML·마크다운이 같은 판정 문장을 쓴다 (검토 11-23)
    assert "판정 대상 1개 항목 중 일치 0개, 불일치 1개, 확인 필요 0개" in h and "판정 대상 1개 항목 중 일치 0개" in md
    assert "기대와 다름" not in md and "<th scope='col'>정상</th>" in h and "<caption" in h and "(불일치)" in h
    assert x.get("failures") == "1"; n += 1
    # 불일치의 영향: 기대와 결과의 방향으로만 정한다. 기대가 'IAM 또는 정책 거부'면 IAM 거부도 일치(채점 기준 고정)
    from gateprobe import view as _v
    imp = lambda exp, obs: _v.impact({"expected": exp, "observed": obs})
    assert imp("ALLOW", "POLICY_DENY") == "허용돼야 할 호출이 차단됨"
    assert imp("IAM_DENY|POLICY_DENY", "ALLOW") == "차단돼야 할 호출이 허용됨"
    assert imp("POLICY_DENY (temporal_forbid)", "IAM_DENY") == "차단 계층 변경"
    assert imp("POLICY_DENY|UNKNOWN [오류 ^400 ]", "ALLOW") == "차단돼야 할 호출이 허용됨"
    assert matches(expectation(["IAM_DENY", "POLICY_DENY"], "A"), "IAM_DENY", None, "") is True; n += 1
    # init: 가짜 AWS로 대상 파일, 변수 파일(git 제외), 시나리오 틀을 만든다. TODO가 남으면 validate 실패
    from gateprobe import scaffold

    class FakeControl:
        def get_gateway(self, gatewayIdentifier):
            if gatewayIdentifier != "gw-123":
                raise KeyError(gatewayIdentifier)
            return {"gatewayId": "gw-123", "name": "my-gw", "gatewayUrl": "https://gw-123.example/mcp",
                    "gatewayArn": "arn:aws:bedrock-agentcore:r:000000000000:gateway/gw-123", "authorizerType": "AWS_IAM",
                    "policyEngineConfiguration": {"arn": "arn:x:policy-engine/pe-1", "mode": "LOG_ONLY"}}

        def list_gateways(self, **kw):
            return {"items": [{"gatewayId": "gw-123", "name": "my-gw"}]}
    tools = {"kind": "TOOLS", "tools": [
        {"name": "t___read_doc", "inputSchema": {"properties": {"key": {}, "note": {}}, "required": ["key"]}},
        {"name": "t___send", "inputSchema": {"properties": {"to": {}, "body": {}}}}]}
    with tempfile.TemporaryDirectory() as d:
        cwd = os.getcwd()
        os.chdir(d)
        try:
            said = []
            got = scaffold.init("my-gw", "r", profile="me", out_dir="checks", control=FakeControl(),
                                list_tools=lambda: tools, log=said.append)
            assert any("LOG_ONLY" in w for w in got["warnings"])
            tgt = Target.load("checks/target.json")
            assert tgt.profile is None and any("--profile me" in m for m in said)   # 프로필은 파일에 넣지 않고 안내에만
            sp = json.load(open("checks/scenarios.json", encoding="utf-8"))
            assert "000000000000" not in open("checks/target.json", encoding="utf-8").read()
            assert tgt.gateway_url("my-gw") == "https://gw-123.example/mcp" and sp["target"] == "t"
            assert sp["scenarios"][0]["steps"][0] == {"tool": "read_doc", "args": {"key": "TODO"}, "expect": "TODO"}
            assert "checks/.gateprobe_vars.json" in open(".gitignore", encoding="utf-8").read()
            errs = validate(sp, tgt)
            assert any("TODO가 남아 있음" in x for x in errs) and not any("'TODO'을 모른다" in x for x in errs)
            # 채우면 통과
            sp["scenarios"] = [{"id": "s", "제목": "문서 읽기", "요약": "허용", "분류": "정상 업무",
                                "steps": [{"tool": "read_doc", "args": {"key": "a"}, "expect": "ALLOW"}]}]
            assert validate(sp, tgt) == []
            # 기대값이 하나도 없으면 형식 검사에서 실패
            sp["scenarios"][0]["steps"][0]["expect"] = None
            assert any("기대값(expect)이 있는 단계가 하나도 없음" in x for x in validate(sp, tgt))
            try:   # 이미 있으면 덮어쓰지 않는다
                scaffold.init("gw-123", "r", out_dir="checks", control=FakeControl(), list_tools=lambda: tools, log=lambda m: None)
                raise AssertionError("덮어씀")
            except FileExistsError:
                pass
        finally:
            os.chdir(cwd)
    n += 1
    # 경로 오타, 깨진 JSON은 추적 정보 없이 설정 오류(3)
    from gateprobe.__main__ import main as cli
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.json")
        open(bad, "w", encoding="utf-8").write("{")
        assert cli(["render", "--record", os.path.join(d, "없음.json"), "--html", os.path.join(d, "o.html")]) == 3
        assert cli(["validate", "--spec", bad, "--target", bad]) == 3
        # --no-deps로 설치해 boto3가 없을 때 AWS 명령은 한 줄 안내 (3)
        saved = {k: sys.modules.get(k) for k in ("boto3",)}
        sys.modules["boto3"] = None
        try:
            assert cli(["init", "--gateway", "x", "--region", "r", "--dir", os.path.join(d, "c")]) == 3
        finally:
            for k, m in saved.items():
                if m is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = m
    n += 1
    # 결과서: 기록 파일 이름이 제목과 머리에, 응답 칸에는 뜻을 먼저
    from gateprobe import view as _v
    assert _v.response_text({"observed": "POLICY_DENY", "rpc_code": -20001}) == "Gateway 정책이 거부 (-20001)"
    assert _v.response_text({"observed": "ALLOW"}) == "도구가 실행되어 성공"
    rec = {"spec": "x", "target": "y", "created_utc": "2026-11-20T00:00:00",
           "configs": {"A": [{"scenario": "s", "step": 1, "tool": "t", "session": "main", "expected": "ALLOW",
                              "observed": "POLICY_DENY", "match": False, "rpc_code": -20001}]},
           "summary": {"calls": 1, "checked": 1, "passed": 0, "regressions": 1, "unknown": 0, "fixture_errors": 0}}
    h = html_report.render(rec, source="record_B.json")
    assert "<title>정책 점검 결과서 · record_B.json</title>" in h and "<th scope='row'>점검 기록</th><td colspan='3'>record_B.json" in h
    assert "Gateway 정책이 거부 (-20001)" in h and "정상이 허용인 항목" in h
    # 항목별 표: '정상' 칸에 차단/허용, 결과도 같은 낱말 (11-20 사용자 요청)
    assert "<th scope='col'>정상</th><th scope='col'>결과</th>" in h and "<td class='c'>허용</td>" in h and ">차단</div>" in h
    assert "막혀야 함" not in h and "허용돼야 함" not in h and "<th>기대</th>" not in h
    n += 1
    # 정책 평가 오류 거부에는 정책 ID가 없다 ("policy"를 ID로 읽지 않음)
    from gateprobe.client import GatewayClient
    c = GatewayClient.__new__(GatewayClient)
    os.environ["GWCHECK_TEST_TOKEN"] = "x"
    GatewayClient.__init__(c, "https://x/mcp", {"type": "bearer", "token_env": "GWCHECK_TEST_TOKEN"}, "r")
    assert c.policy_id.search("[Authorization denied due to policy evaluation errors: Value does not match]") is None
    assert c.policy_id.search("[Policy evaluation denied due to cap_x_forbid-10zflnswvt]").group(1) == "cap_x_forbid-10zflnswvt"
    n += 1
    # MCP 버전 (외부 예제 A, 11-23): 대상 파일로 고르고, 보낸 헤더와 _meta가 그 버전, 거부되면 안내
    import io
    import gateprobe.client as gc
    from urllib.error import HTTPError
    sent = []

    class _Resp:
        def __init__(self, body): self.status, self._b = 200, body
        def read(self, n=-1): return self._b
        def __enter__(self): return self
        def __exit__(self, *x): return False

    def fake_urlopen(req, timeout=None):
        body = json.loads(req.data)
        sent.append((req.headers, body))
        hdr = {k.lower(): v for k, v in req.headers.items()}
        if hdr.get("mcp-protocol-version") != "2025-11-25":
            raw = ('{"jsonrpc":"2.0","id":"%s","error":{"code":-32600,"message":"Unsupported protocol version: %s",'
                   '"data":{"supported":["2025-11-25"],"requested":"%s"}}}' % (body["id"], hdr.get("mcp-protocol-version"),
                                                                             hdr.get("mcp-protocol-version")))
            raise HTTPError(req.full_url, 400, "Bad Request", {}, io.BytesIO(raw.encode()))
        return _Resp(json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "w___WebSearch"}]}}).encode())

    saved_open = gc.urlopen
    gc.urlopen = fake_urlopen
    try:
        old = GatewayClient("https://x/mcp", {"type": "bearer", "token_env": "GWCHECK_TEST_TOKEN"}, "r")
        got = old.list_tools()
        assert got["kind"] == "TRANSPORT_ERROR" and got["http_status"] == 400
        assert got["hint"] == '이 Gateway가 받는 MCP 버전: 2025-11-25. 대상 파일에 "mcp_version": "2025-11-25"을 적는다'
        new = GatewayClient("https://x/mcp", {"type": "bearer", "token_env": "GWCHECK_TEST_TOKEN"}, "r", mcp_version="2025-11-25")
        assert new.list_tools() == {"kind": "TOOLS", "tools": [{"name": "w___WebSearch"}]}
        assert sent[-1][1]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2025-11-25"
    finally:
        gc.urlopen = saved_open
    try:
        GatewayClient("https://x/mcp", {"type": "bearer", "token_env": "GWCHECK_TEST_TOKEN"}, "r", mcp_version="1999-01-01")
        raise AssertionError("모르는 버전을 받음")
    except ValueError:
        pass
    assert any("mcp_version 모름" in e for e in validate({"scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "ALLOW"}]}]},
                                                         Target({"region": "r", "gateways": {"A": "https://a/mcp"}, "mcp_version": "x"})))
    # init: Gateway 설정의 지원 버전을 읽어 대상 파일에 적는다. 모르는 버전뿐이면 주의
    for supported, want, warn in ((["2025-11-25"], "2025-11-25", False), (["2025-11-25", "2026-07-28"], "2026-07-28", False),
                                  (["1999-01-01"], None, True)):
        class Ctl(FakeControl):
            def get_gateway(self, gatewayIdentifier, _s=supported):
                g = FakeControl.get_gateway(self, gatewayIdentifier)
                return {**g, "protocolConfiguration": {"mcp": {"supportedVersions": _s}}}
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                got = scaffold.init("gw-123", "r", out_dir="c", control=Ctl(), list_tools=lambda: tools, log=lambda m: None)
                assert Target.load("c/target.json").mcp_version == want
                assert any("MCP 버전" in w for w in got["warnings"]) == warn
            finally:
                os.chdir(cwd)
    n += 1
    # 도구 오류 문구는 기록에 남기고 응답 칸에 보인다. 성공 결과 본문은 남기지 않는다 (B의 업무·인프라 오류 구분용)
    tl = []
    sp = {"name": "s", "scenarios": [{"id": "x", "steps": [{"tool": "bad", "args": {}, "expect": "ALLOW"},
                                                         {"tool": "good", "args": {}, "expect": "ALLOW"}]}]}
    tab = {("A", "bad"): res(text="insufficient funds", is_error=True), ("A", "good"): res({"ok": True}, text="secret body")}
    rec = runner.run(sp, make_target(gateways={"A": "https://a/mcp"}), ["A"], lambda g: FakeGateway(g, tab, tl), None)
    rows = rec["configs"]["A"]
    assert rows[0]["observed"] == "TOOL_ERROR" and rows[0]["tool_text"] == "insufficient funds" and rows[1]["tool_text"] is None
    from gateprobe import view as _v2
    assert _v2.response_text({**rows[0], "http_status": 200}) == "도구가 오류를 돌려줌 (insufficient funds)"
    n += 1
    # 편의 개선 2: 도구 설명으로 인자 예시를 채운다. 문자열은 설명을 붙인 TODO
    assert scaffold._args({"inputSchema": {"properties": {
        "account_id": {"type": "string", "description": "Account to read"}, "amount": {"type": "number", "minimum": 0},
        "limit": {"type": "integer", "default": 10}, "side": {"type": "string", "enum": ["BUY", "SELL"]},
        "dry": {"type": "boolean"}, "tags": {"type": "array"}, "x": {}}}}) == {
        "account_id": "TODO: Account to read", "amount": 0, "limit": 10, "side": "BUY", "dry": False, "tags": [], "x": "TODO"}
    n += 1
    # 편의 개선 1: JWT Gateway면 init이 discoveryUrl에서 토큰 주소를 찾아 oauth로 적는다. 못 찾으면 수동 토큰(bearer)
    for found, want in (({"token_endpoint": "https://idp.example/oauth2/token"}, "oauth"), (None, "bearer")):
        class JwtCtl(FakeControl):
            def get_gateway(self, gatewayIdentifier):
                return {**FakeControl.get_gateway(self, gatewayIdentifier), "authorizerType": "CUSTOM_JWT",
                        "authorizerConfiguration": {"customJWTAuthorizer": {"discoveryUrl": "https://idp.example/.well-known/openid-configuration",
                                                                            "allowedClients": ["c1"]}}}

        def fake_fetch(url, _f=found):
            if _f is None:
                raise OSError("no network")
            return _f
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                said = []
                scaffold.init("gw-123", "r", out_dir="c", control=JwtCtl(), list_tools=lambda: tools, log=said.append, fetch=fake_fetch)
                tg = Target.load("c/target.json")
                assert tg.auth["type"] == want
                if want == "oauth":
                    assert tg.auth["token_url"] == "https://idp.example/oauth2/token" and any("GW_CLIENT_ID" in m for m in said)
                assert validate({"scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "ALLOW"}]}]}, tg) == []
            finally:
                os.chdir(cwd)
    # oauth 토큰: 받아서 쓰고, 만료 전에는 다시 받지 않으며, 만료가 가까우면 새로 받는다. 비밀값은 Basic 헤더로만
    issued = []

    def fake_open2(req, timeout=None):
        if req.full_url.endswith("/oauth2/token"):
            issued.append(dict(req.headers))
            return _Resp(json.dumps({"access_token": f"tok{len(issued)}", "expires_in": 3600}).encode())
        body = json.loads(req.data)
        sent.append((req.headers, body))
        return _Resp(json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}}).encode())
    os.environ["GWCHECK_T_ID"], os.environ["GWCHECK_T_SECRET"] = "cid", "csecret\r"
    gc.urlopen = fake_open2
    try:
        oc = GatewayClient("https://x/mcp", {"type": "oauth", "token_url": "https://idp.example/oauth2/token",
                                             "client_id_env": "GWCHECK_T_ID", "client_secret_env": "GWCHECK_T_SECRET"}, "r",
                           mcp_version="2025-11-25")
        oc.list_tools(); oc.list_tools()
        assert len(issued) == 1 and {k.lower(): v for k, v in sent[-1][0].items()}["authorization"] == "Bearer tok1"
        import base64 as _b
        assert {k.lower(): v for k, v in issued[0].items()}["authorization"] == "Basic " + _b.b64encode(b"cid:csecret").decode()
        oc.oauth._until = 0
        oc.list_tools()
        assert len(issued) == 2 and {k.lower(): v for k, v in sent[-1][0].items()}["authorization"] == "Bearer tok2"
    finally:
        gc.urlopen = saved_open
    try:
        os.environ.pop("GWCHECK_T_SECRET")
        GatewayClient("https://x/mcp", {"type": "oauth", "token_url": "https://t", "client_id_env": "GWCHECK_T_ID",
                                        "client_secret_env": "GWCHECK_T_SECRET"}, "r")
        raise AssertionError("비밀값 없이 만들어짐")
    except RuntimeError as exc:
        assert "GWCHECK_T_SECRET" in str(exc)
    n += 1
    # 편의 개선 4: 입구 인증·권한 거부를 한 줄 안내로
    assert "다시 로그인" in gc.auth_hint(401, '{"error":{"code":-32001,"message":"Authentication error - Invalid credentials"}}', "sigv4")
    assert "allowedClients" in gc.auth_hint(401, "", "oauth")
    assert "InvokeGateway" in gc.auth_hint(403, '{"error":{"code":-32002}}', "sigv4")
    assert gc.auth_hint(500, "boom", "sigv4") is None
    n += 1
    # 편의 개선 3: observe는 TODO 기대값 옆에 지금 결과를 적고 TODO는 남긴다. 인자 TODO에서 그 시나리오를 멈춘다
    ol = []
    osp = {"name": "o", "scenarios": [
        {"id": "a", "steps": [{"tool": "read", "args": {}, "expect": "ALLOW"}, {"tool": "send", "args": {}, "expect": "TODO"}]},
        {"id": "b", "steps": [{"tool": "read", "args": {"k": "TODO"}, "expect": "TODO"}, {"tool": "send", "args": {}, "expect": "TODO"}]}]}
    otab = {("A", "send"): deny()}
    obs_spec, cnt = runner.observe(osp, make_target(gateways={"A": "https://a/mcp"}), "A", FakeGateway("A", otab, ol), log=lambda m: None)
    a_steps, b_steps = obs_spec["scenarios"][0]["steps"], obs_spec["scenarios"][1]["steps"]
    # 기대값은 "TODO" 한 낱말 그대로, 지금 결과는 따로 (JSON 편집 실수를 줄이려고, 검토 11-23)
    assert a_steps[0]["expect"] == "ALLOW" and "지금결과" not in a_steps[0]
    assert a_steps[1]["expect"] == "TODO" and a_steps[1]["지금결과"] == "POLICY_DENY (정책 차단)"
    assert all(s["expect"] == "TODO" and s["지금결과"].startswith("호출 안 함") for s in b_steps)
    assert cnt == {"observed": 1, "skipped": 2, "calls": 2}
    assert len(ol) == 2 and ol[0][3] == ol[1][3]   # 시나리오 a의 두 호출만, 같은 정책 세션
    assert osp["scenarios"][0]["steps"][1]["expect"] == "TODO"   # 원본은 그대로
    # 호출 전 계획: TODO 없는 시나리오는 건너뛰고, 마지막 TODO 단계 뒤는 보내지 않는다 (외부 검토 11-23)
    plan_spec = {"name": "p", "scenarios": [
        {"id": "done", "steps": [{"tool": "read", "args": {}, "expect": "ALLOW"}]},
        {"id": "mid", "steps": [{"tool": "read", "args": {}, "expect": "ALLOW"}, {"tool": "send", "args": {}, "expect": "TODO"},
                                {"tool": "delete", "args": {}, "expect": "POLICY_DENY"}]}]}
    pl = runner.observe_plan(plan_spec)
    assert [p["id"] for p in pl] == ["mid"] and pl[0]["calls"] == [(1, "read"), (2, "send")]
    ol2 = []
    runner.observe(plan_spec, make_target(gateways={"A": "https://a/mcp"}), "A", FakeGateway("A", {}, ol2), log=lambda m: None)
    assert [c[1] for c in ol2] == ["read", "send"]   # delete는 보내지 않음
    # observe도 run처럼 사전 객체를 먼저 올리고, 같은 {ns}로 읽는다. 올리지 못하면 그 시나리오는 호출하지 않는다 (11-25)
    fx_spec = {"name": "f", "fixtures": [{"bucket": "b", "key": "docs/{ns}/r.txt", "body": "x"}], "scenarios": [
        {"id": "f1", "steps": [{"tool": "read", "args": {"key": "docs/{ns}/r.txt"}, "expect": "ALLOW"},
                               {"tool": "send", "args": {}, "expect": "TODO"}]},
        {"id": "f2", "steps": [{"tool": "send", "args": {}, "expect": "TODO"}]}]}
    puts, ol3 = [], []
    runner.observe(fx_spec, make_target(gateways={"A": "https://a/mcp"}), "A", FakeGateway("A", {}, ol3), log=lambda m: None,
                   put_fixture=lambda b, k, body: puts.append((b, k, body)))
    assert len(puts) == 2 and puts[0][1] == ol3[0][2]["key"], (puts, ol3)   # 시나리오마다 한 번, 읽는 키와 같음
    def bad_put(b, k, body):
        raise PermissionError("AccessDenied")
    ol4 = []
    fo, fc = runner.observe(fx_spec, make_target(gateways={"A": "https://a/mcp"}), "A", FakeGateway("A", {}, ol4), log=lambda m: None,
                            put_fixture=bad_put)
    assert ol4 == [] and fc["skipped"] == 2 and "사전 객체" in fo["scenarios"][0]["steps"][1]["지금결과"]
    # CLI: TODO가 없으면 호출 없이 끝나고, 저장 파일이 이미 있으면 호출 전에 멈춘다
    with tempfile.TemporaryDirectory() as d:
        tp, sp0 = os.path.join(d, "t.json"), os.path.join(d, "s.json")
        json.dump({"name": "t", "region": "r", "auth": {"type": "bearer", "token_env": "GWCHECK_TEST_TOKEN"},
                   "gateways": {"G": "https://g/mcp"}}, open(tp, "w", encoding="utf-8"))
        json.dump({"name": "s", "scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "ALLOW"}]}]},
                  open(sp0, "w", encoding="utf-8"))
        saved_urlopen = gc.urlopen
        gc.urlopen = lambda *x, **k: (_ for _ in ()).throw(AssertionError("호출하면 안 됨"))
        try:
            assert cli(["observe", "--spec", sp0, "--target", tp, "--execute"]) == 0
            json.dump({"name": "s", "scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "TODO"}]}]},
                      open(sp0, "w", encoding="utf-8"))
            open(os.path.join(d, "s_observed.json"), "w").write("{}")
            assert cli(["observe", "--spec", sp0, "--target", tp, "--execute"]) == 3
        finally:
            gc.urlopen = saved_urlopen
    assert any("TODO" in e for e in validate(obs_spec, make_target(gateways={"A": "https://a/mcp"})))
    n += 1
    # 편의 개선 4: doctor는 자격 증명, 접속, 정책 엔진, 버전 문제를 [통과]/[주의]/[실패]로
    from gateprobe import doctor

    class DocClient:
        def __init__(self, got): self.got = got
        def list_tools(self): return self.got

    class DocCtl:
        def get_gateway(self, gatewayIdentifier):
            assert gatewayIdentifier == "gw-abc"
            return {"policyEngineConfiguration": {"arn": "arn:pe", "mode": "LOG_ONLY"},
                    "protocolConfiguration": {"mcp": {"supportedVersions": ["2025-11-25"]}}}
    dt = make_target(gateways={"G": "https://gw-abc.gateway.bedrock-agentcore.r.amazonaws.com/mcp"})
    lines = []
    fails = doctor.run_doctor(dt, ["G"], lambda g: DocClient({"kind": "TOOLS", "tools": [{"name": "t___a"}]}),
                              lambda: "arn:aws:sts::123456789012:assumed-role/x", DocCtl(), log=lines.append)
    text = "\n".join(lines)
    assert fails == 1 and "[통과] AWS 신원: arn:aws:sts::<ACCOUNT>" in text and "LOG_ONLY" in text
    assert "\"mcp_version\": \"2025-11-25\"" in text   # 대상 파일 기본 2026-07-28을 Gateway가 받지 않음
    # 마지막 줄에 실패·주의 개수와 집행 모드 (외부 검토 11-23: LOG_ONLY가 '문제 없음'에 묻히지 않게)
    assert lines[-1].startswith("진단 끝: 실패 1개, 주의 1개") and "LOG_ONLY(막지 않음)" in lines[-1]
    # 사전 준비 실패 예외의 계정 ID는 결과서에서 가린다
    from gateprobe import view as _v3
    vv = _v3.build({"configs": {"A": [{"scenario": "s", "step": 0, "tool": "(fixtures)", "expected": None, "observed": "UNKNOWN",
                                       "match": None, "error": "AccessDenied arn:aws:s3:::b-123456789012/x"}]},
                    "summary": {"calls": 0, "checked": 0, "passed": 0, "regressions": 0, "unknown": 0, "fixture_errors": 1}})
    assert "123456789012" not in vv["issues"][0]["response"] and "<ACCOUNT>" in vv["issues"][0]["response"]
    lines.clear()
    fails = doctor.run_doctor(dt, ["G"], lambda g: DocClient({"kind": "TRANSPORT_ERROR", "http_status": 403, "detail": "x",
                                                              "hint": gc.auth_hint(403, "", "sigv4")}),
                              lambda: "arn:x", None, log=lines.append)
    assert fails == 1 and "InvokeGateway" in "\n".join(lines)
    lines.clear()

    def no_creds():
        raise RuntimeError("Unable to locate credentials")
    assert doctor.run_doctor(dt, ["G"], None, no_creds, None, log=lines.append) == 1 and "aws login" in "\n".join(lines)
    n += 1
    # 토큰 환경 변수가 없으면 추적 정보 대신 한 줄 안내와 설정 오류(3)
    with tempfile.TemporaryDirectory() as d:
        tp, sp_ = os.path.join(d, "t.json"), os.path.join(d, "s.json")
        json.dump({"name": "t", "region": "r", "auth": {"type": "oauth", "token_url": "https://idp/oauth2/token",
                   "client_id_env": "GWCHECK_NONE_ID", "client_secret_env": "GWCHECK_NONE_SECRET"},
                   "gateways": {"G": "https://g/mcp"}}, open(tp, "w", encoding="utf-8"))
        json.dump({"name": "s", "scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "ALLOW"}]}]},
                  open(sp_, "w", encoding="utf-8"))
        assert cli(["run", "--spec", sp_, "--target", tp, "--execute", "--out", os.path.join(d, "o.json")]) == 3
    n += 1
    # AWS 로그인 만료(botocore 오류)는 종료 코드 1(부적합)이 아니라 3(설정 오류)과 한 줄 안내 (11-24 발견)
    CredErr = type("CredentialRetrievalError", (Exception,), {"__module__": "botocore.exceptions"})
    saved_init = gc.GatewayClient.__init__

    def expired(self, *a, **k):
        raise CredErr("Error when retrieving credentials\naws: [ERROR]: Your session has expired.")
    gc.GatewayClient.__init__ = expired
    try:
        with tempfile.TemporaryDirectory() as d:
            tp, sp_ = os.path.join(d, "t.json"), os.path.join(d, "s.json")
            json.dump({"name": "t", "region": "r", "gateways": {"G": "https://g/mcp"}}, open(tp, "w", encoding="utf-8"))
            json.dump({"name": "s", "scenarios": [{"id": "s", "steps": [{"tool": "t", "args": {}, "expect": "ALLOW"}]}]},
                      open(sp_, "w", encoding="utf-8"))
            assert cli(["run", "--spec", sp_, "--target", tp, "--execute", "--out", os.path.join(d, "o.json")]) == 3
    finally:
        gc.GatewayClient.__init__ = saved_init
    n += 1
    # 단계별 wait: 호출 전에 기다리고, 형식이 틀리면 validate가 잡는다
    import time as _t
    wsp = {"name": "w", "scenarios": [{"id": "w", "steps": [{"tool": "a", "args": {}, "expect": "ALLOW", "wait": 0.3}]}]}
    t0 = _t.time()
    runner.run(wsp, make_target(gateways={"A": "https://a/mcp"}), ["A"], lambda g: FakeGateway(g, {}, []), None, log=lambda m: None)
    assert _t.time() - t0 >= 0.3 and validate(wsp, make_target()) == []
    wsp["scenarios"][0]["steps"][0]["wait"] = "5분"
    assert any("wait는" in e for e in validate(wsp, make_target()))
    n += 1
    print(f"gateprobe 테스트 통과 ({n}개)")


if __name__ == "__main__":
    run_tests()
