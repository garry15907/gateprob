"""gateprobe: AgentCore Gateway 정책 회귀 점검 (모델 없이 고정 호출)

  python -m gateprobe validate --spec S.json --target T.json           형식 검사 (AWS 접속 없음)
  python -m gateprobe run --spec S.json --target T.json                계획만 출력
  python -m gateprobe run --spec S.json --target T.json --execute      실제 호출
      [--gateways a,b] [--out rec.json] [--junit rep.xml] [--summary sum.md]
  python -m gateprobe tools --target T.json --gateway NAME             Gateway의 도구 목록 (시나리오 작성용)

  python -m gateprobe init --gateway ID --region R                     대상 파일, 변수 파일, 시나리오 틀 만들기
  python -m gateprobe doctor --target T.json                           실행 전 진단 (자격 증명, 접속, 버전, 정책 엔진)
  python -m gateprobe observe --spec S.json --target T.json --execute  TODO 기대값 옆에 '지금 결과'를 적은 초안 만들기
  python -m gateprobe ui --spec S.json [--draft S_observed.json]       정상 확인 화면 (초안을 보며 정상을 골라 원본에 저장)
  python -m gateprobe render --record rec.json --html out.html         기록으로 결과서 다시 만들기

종료 코드: 0 적합, 1 부적합(정상과 다른 허용/차단), 2 점검 미완료(판정 불가, 사전 준비 실패, 정상을 정한 호출 0개),
3 설정 오류(형식, TODO, 파일 없음)
GITHUB_STEP_SUMMARY 환경 변수가 있으면 요약을 거기에도 덧붙인다 (GATEPROBE_STEP_SUMMARY=0이면 안 씀. 옛 이름 GWCHECK_STEP_SUMMARY도 받음).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from gateprobe import html_report, report, runner
from gateprobe.client import GatewayClient
from gateprobe.spec import Target, describe, expectation, tool_name, validate


def _load(a):
    spec = json.load(open(a.spec, encoding="utf-8"))
    target = Target.load(a.target)
    if getattr(a, "profile", None):
        target.profile = target.fixture_profile = a.profile
    gateways = a.gateways.split(",") if getattr(a, "gateways", None) else list(target.gateways_raw)
    missing = [g for g in gateways if g not in target.gateways_raw]
    if missing:
        raise SystemExit(f"대상에 없는 Gateway: {missing}")
    return spec, target, gateways


def cmd_validate(a):
    spec, target, gateways = _load(a)
    errors = validate(spec, target, gateways)
    for msg, where in _group_errors(errors):
        print("오류:", msg + (f"  ({len(where)}곳: {', '.join(where[:5])}{' 등' if len(where) > 5 else ''})" if where else ""))
    print(f"{spec.get('name')}: 시나리오 {len(spec.get('scenarios', []))}개, Gateway {len(gateways)}개, 오류 {len(errors)}개")
    return 3 if errors else 0


def _group_errors(errors):
    """같은 오류가 여러 단계에서 나면 한 줄로 묶는다 (검토 11-23: 같은 오타 17줄)."""
    import re as _re

    groups = {}
    for e in errors:
        m = _re.match(r"^(\S+ \d+단계): (.*)$", e)
        where, msg = (m.group(1), m.group(2)) if m else (None, e)
        groups.setdefault(msg, [])
        if where:
            groups[msg].append(where)
    return list(groups.items())


def cmd_run(a):
    spec, target, gateways = _load(a)
    errors = validate(spec, target, gateways)
    if errors:
        for e in errors:
            print("오류:", e)
        return 3
    print("모드:", "실행" if a.execute else "계획만", "|", spec.get("name"), "| 대상", target.name, "| Gateway", ",".join(gateways))
    if not a.execute:   # 실행할 때는 호출마다 결과 줄이 나오므로 계획을 따로 찍지 않는다 (검토 11-23: 같은 내용이 두 번)
        for sc in spec["scenarios"]:
            print(f"  {sc['id']}")
            for i, st in enumerate(sc["steps"], 1):
                exp = " ".join(f"{g}={describe(expectation(st.get('expect'), g))}" for g in gateways)
                print(f"    {i} {tool_name(spec, st['tool'])}  {exp}")
        print("실제로 보내려면 --execute를 붙인다")
        return 0
    put = runner.s3_putter(target.fixture_profile, target.region) if spec.get("fixtures") else None
    make = lambda gw: GatewayClient(target.gateway_url(gw), target.auth, target.region, target.profile,
                                    policy_id_pattern=target.policy_id_pattern, mcp_version=target.mcp_version)
    record = runner.run(spec, target, gateways, make, put, a.spec, log=lambda m: print(m, flush=True))
    out = a.out or os.path.join("gateprobe_out", datetime.now().strftime("gateprobe_%Y%m%d-%H%M%S.json"))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "x", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    if a.junit:
        with open(a.junit, "w", encoding="utf-8") as f:
            f.write(report.junit(record))
    look = (target.data.get("labels"), {sc["id"]: sc for sc in spec["scenarios"]}, target.data.get("tool_labels"), spec.get("분류"))
    md = report.markdown(record, *look)
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(html_report.render(record, *look))
    if a.summary:
        with open(a.summary, "w", encoding="utf-8") as f:
            f.write(md)
    if os.environ.get("GITHUB_STEP_SUMMARY") and os.environ.get("GATEPROBE_STEP_SUMMARY", os.environ.get("GWCHECK_STEP_SUMMARY", "1")) != "0":   # 0이면 workflow가 직접 요약을 쓴다
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    s = record["summary"]
    from gateprobe import view

    v = view.build(record, *look)   # 결과서 첫 줄과 같은 문장 (검토 11-23)
    code = runner.exit_code(s)
    print(f"결론: {v['head']} — {v['line']}")
    print(f"호출 {s['calls']}번 중 정상을 정해 둔 호출 {s['checked']}번: 일치 {s['passed']}, 불일치 {s['regressions']}, "
          f"확인 필요 {s['unknown'] + s['fixture_errors']}")
    print(f"저장: {out}" + (f", 결과서 {a.html}" if a.html else "") + f" | 종료 코드 {code} "
          f"({ {0: '적합', 1: '불일치 있음', 2: '점검 미완료'}.get(code, '') })")
    for hint in dict.fromkeys(r["hint"] for rows in record["configs"].values() for r in rows if r.get("hint")):
        print("안내:", hint)
    return code


def cmd_render(a):
    record = html_report.summarize_legacy(json.load(open(a.record, encoding="utf-8")))
    tdata = json.load(open(a.target, encoding="utf-8")) if a.target else {}
    labels, tool_labels = tdata.get("labels"), tdata.get("tool_labels")
    sdata = json.load(open(a.spec, encoding="utf-8")) if a.spec else {}
    notes = {sc["id"]: sc for sc in sdata.get("scenarios", [])}
    with open(a.html, "w", encoding="utf-8") as f:
        f.write(html_report.render(record, labels, notes, tool_labels, sdata.get("분류"), source=os.path.basename(a.record)))
    print("저장:", a.html)
    return 0


def cmd_tools(a):
    target = Target.load(a.target)
    if a.profile:
        target.profile = a.profile
    client = GatewayClient(target.gateway_url(a.gateway), target.auth, target.region, target.profile,
                           policy_id_pattern=target.policy_id_pattern, mcp_version=target.mcp_version)
    got = client.list_tools()
    if got.get("kind") != "TOOLS":
        print("목록 조회 실패:", json.dumps(got, ensure_ascii=False)[:500])
        if got.get("hint"):
            print("안내:", got["hint"])
        return 2
    for t in got["tools"]:
        props = (t.get("inputSchema") or {}).get("properties", {})
        print(f"{t['name']}  인자: {', '.join(props) or '-'}")
    return 0


def _make_client(target):
    return lambda gw: GatewayClient(target.gateway_url(gw), target.auth, target.region, target.profile,
                                    policy_id_pattern=target.policy_id_pattern, mcp_version=target.mcp_version)


def cmd_doctor(a):
    from gateprobe import doctor

    target = Target.load(a.target)
    if a.profile:
        target.profile = a.profile
    gateways = a.gateways.split(",") if a.gateways else list(target.gateways_raw)
    control = None

    def identity():
        raise RuntimeError("boto3가 설치되어 있지 않다(--no-deps 설치). AWS 명령을 쓰려면 --no-deps 없이 다시 설치한다")
    try:
        import boto3

        sess = boto3.Session(profile_name=target.profile, region_name=target.region)
        identity = lambda: sess.client("sts").get_caller_identity()["Arn"]
        if sess.get_credentials() is not None:
            control = sess.client("bedrock-agentcore-control")
    except ImportError:
        pass
    fails = doctor.run_doctor(target, gateways, _make_client(target), identity, control)
    return 2 if fails else 0


def cmd_observe(a):
    spec, target, gateways = _load(a)
    if len(gateways) != 1:
        if a.gateways:
            raise SystemExit("observe는 Gateway 하나씩 돌린다: --gateways에 하나만 적는다")
        gateways = gateways[:1]
    out = a.out or os.path.splitext(a.spec)[0] + "_observed.json"
    if os.path.abspath(out) == os.path.abspath(a.spec):
        raise SystemExit("원래 시나리오 파일을 덮어쓰지 않는다. --out에 다른 경로를 준다")
    # 호출하기 전에 막을 것을 먼저 본다 (외부 검토 11-23: 호출 뒤에 저장이 실패하면 다시 실행할 때 같은 호출이 또 나간다)
    if os.path.exists(out):
        print(f"저장할 파일이 이미 있다: {out}. 지우거나 --out에 다른 경로를 준 뒤 다시 실행한다 (호출은 보내지 않았다)")
        return 3
    plan = runner.observe_plan(spec)
    todo = sum(p["todo"] for p in plan)
    n_calls = sum(len(p["calls"]) for p in plan)
    if not todo:
        print("기대값이 TODO인 단계가 없다. 관찰할 것이 없어 호출하지 않았다")
        return 0
    print(f"Gateway {gateways[0]}에 호출 {n_calls}번을 보내 TODO 기대값 {todo}개의 지금 결과를 적는다 "
          f"(인자가 TODO라 못 보는 것 {sum(p['skipped'] for p in plan)}개):")
    for p in plan:
        if p["calls"]:
            print(f"  {p['id']}: " + " → ".join(t for _, t in p["calls"]))
    if spec.get("fixtures"):
        print(f"호출 전에 시나리오마다 사전 객체 {len(spec['fixtures'])}개를 S3에 올린다 (run과 같음)")
    print("주의: 삭제·송금처럼 되돌릴 수 없는 도구도 그대로 실행된다. 시험용 데이터와 시험용 Gateway에서만 쓴다.")
    if not a.execute:
        print("실제로 보내려면 --execute를 붙인다")
        return 0
    put = runner.s3_putter(target.fixture_profile, target.region) if spec.get("fixtures") else None
    observed, counts = runner.observe(spec, target, gateways[0], _make_client(target)(gateways[0]),
                                      log=lambda m: print(m, flush=True), put_fixture=put, spec_path=a.spec)
    with open(out, "x", encoding="utf-8") as f:
        json.dump(observed, f, ensure_ascii=False, indent=2)
    print(f"저장: {out} | 호출 {counts['calls']}번, 지금 결과를 적은 단계 {counts['observed']}개, 못 본 단계 {counts['skipped']}개")
    print(f"다음: 화면에서 정상을 고른다 (원본 {a.spec}의 정상 칸만 바뀐다):")
    print(f"  gateprobe ui --spec \"{a.spec}\" --draft \"{out}\" --target \"{a.target}\"")
    print(f"  화면 없이 하려면 원본에서 \"expect\": \"TODO\"인 단계마다 {out}의 \"지금결과\"를 참고해 정상값(예: \"ALLOW\")을 적는다")
    return 0


def cmd_ui(a):
    from gateprobe import ui_server
    draft = a.draft or os.path.splitext(a.spec)[0] + "_observed.json"
    if os.path.normcase(os.path.abspath(draft)) == os.path.normcase(os.path.abspath(a.spec)):
        print("원본과 초안이 같은 파일이다. --draft에 observe가 만든 초안을 준다")
        return 3
    for path, what in ((a.spec, "원본 시나리오"), (draft, "observe 초안")):
        if not os.path.exists(path):
            print(f"{what} 파일이 없다: {path}")
            if what == "observe 초안":
                print(f"먼저 gateprobe observe --spec \"{a.spec}\" --target <대상 파일> --execute로 초안을 만든다")
            return 3
        json.load(open(path, encoding="utf-8"))   # 형식 오류는 여기서 한 줄로 (main의 JSONDecodeError 처리)
    return ui_server.serve(a.spec, draft, a.target, a.port, not a.no_browser)


def cmd_init(a):
    from gateprobe import scaffold

    try:
        scaffold.init(a.gateway, a.region, a.profile, a.dir, a.force)
    except (LookupError, FileExistsError, ValueError, RuntimeError) as exc:
        print("init 실패:", exc)
        return 3
    except Exception as exc:   # boto3 자격 증명, 권한 오류는 추적 정보 대신 할 일을 알려 준다
        if type(exc).__module__.startswith("botocore"):
            print("AWS 접속 실패:", str(exc).strip().splitlines()[-1][:300])
            print("aws login(또는 aws sso login)으로 로그인했는지, --profile과 --region이 맞는지 확인할 것")
            return 2
        raise
    return 0


def _fix_console():
    """Git Bash(mintty)에서는 출력이 파이프라 Windows 기본 인코딩(cp949)으로 나가 한글이 깨진다. 그때만 UTF-8로.
    그 밖에는 인코딩을 그대로 두고, 표현할 수 없는 글자 때문에 멈추지 않게만 한다."""
    for s in (sys.stdout, sys.stderr):
        if not hasattr(s, "reconfigure"):
            continue
        try:
            if os.environ.get("MSYSTEM") and not s.isatty():
                s.reconfigure(encoding="utf-8", errors="replace")
            elif (s.encoding or "").lower().replace("-", "") != "utf8":
                s.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


HELP = {
    "validate": "시나리오 파일과 대상 파일의 형식 검사 (AWS 접속 없음)",
    "run": "점검 실행. --execute가 없으면 보낼 호출 계획만 출력",
    "render": "저장된 점검 기록(JSON)으로 HTML 결과서를 만든다 (AWS 접속 없음)",
    "init": "Gateway 정보를 읽어 대상 파일, 변수 파일(git 제외), 시나리오 틀을 만든다",
    "tools": "Gateway의 도구 이름과 인자 목록 (시나리오 작성용)",
    "doctor": "실행 전 진단: 대상 파일, 자격 증명·토큰, Gateway 접속, MCP 버전, 정책 엔진 모드. 문제마다 고치는 법",
    "observe": "기대값이 TODO인 단계를 한 번 호출해 '지금 결과'를 적은 초안 시나리오를 새 파일로 만든다 (--execute 필요)",
    "ui": "정상 확인 화면: observe 초안의 지금 결과를 보며 단계마다 정상을 고르고 원본에 저장한다 (이 컴퓨터에서만 열림, AWS 접속 없음)",
}


def main(argv=None):
    _fix_console()
    # 도움말의 argparse 영어 문구를 한국어로 (검토 11-23)
    p = argparse.ArgumentParser(prog="gateprobe", add_help=False,
                                description="AgentCore Gateway 정책 점검. 명령마다 자세한 옵션: gateprobe <명령> --help")
    p.add_argument("-h", "--help", action="help", help="이 도움말을 보이고 끝낸다")
    p._positionals.title, p._optionals.title = "명령", "옵션"
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<명령>")
    _add = sub.add_parser

    def _korean_parser(name, **kw):
        q = _add(name, add_help=False, **kw)
        q.add_argument("-h", "--help", action="help", help="이 도움말을 보이고 끝낸다")
        q._optionals.title = "옵션"
        return q
    sub.add_parser = _korean_parser
    SPEC, TARGET = "시나리오 파일(JSON): 보낼 호출과 정상(차단/허용)", "대상 파일(JSON): Gateway 주소, 인증, 지역"
    PROFILE = "AWS 프로필 이름 (대상 파일에 적지 않고 실행할 때만 쓴다)"
    # 도움말 목록은 쓰는 순서대로 (검토 11-23)
    q = sub.add_parser("init", help=HELP["init"], description=HELP["init"])
    q.add_argument("--gateway", required=True, help="Gateway ID, ARN 또는 이름")
    q.add_argument("--region", required=True, help="AWS 지역 (예: ap-northeast-1)")
    q.add_argument("--profile", help="AWS 프로필 (없으면 기본 자격 증명)")
    q.add_argument("--dir", default="checks", help="파일을 만들 폴더 (기본 checks)")
    q.add_argument("--force", action="store_true", help="이미 있는 파일을 덮어쓴다")
    q = sub.add_parser("doctor", help=HELP["doctor"], description=HELP["doctor"])
    q.add_argument("--target", required=True, help=TARGET)
    q.add_argument("--gateways", help="쉼표로 구분. 기본은 대상의 모든 Gateway")
    q.add_argument("--profile", help=PROFILE)
    q = sub.add_parser("observe", help=HELP["observe"], description=HELP["observe"])
    q.add_argument("--spec", required=True, help=SPEC)
    q.add_argument("--target", required=True, help=TARGET)
    q.add_argument("--gateways", help="Gateway 하나. 기본은 대상의 첫 Gateway")
    q.add_argument("--profile", help=PROFILE)
    q.add_argument("--out", help="저장할 새 시나리오 파일 (기본: <시나리오>_observed.json)")
    q.add_argument("--execute", action="store_true", help="실제로 호출한다 (없으면 보낼 호출만 보여 준다)")
    q = sub.add_parser("ui", help=HELP["ui"], description=HELP["ui"])
    q.add_argument("--spec", required=True, help="원본 시나리오 파일. 화면에서 고른 정상이 이 파일에 저장된다")
    q.add_argument("--draft", help="observe가 만든 초안 (기본: <원본>_observed.json)")
    q.add_argument("--target", help="대상 파일. 주면 저장 뒤 형식 검사에서 Gateway 이름까지 본다")
    q.add_argument("--port", type=int, default=0, help="포트 (기본 0: 빈 포트를 골라 씀)")
    q.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않는다 (주소만 출력)")
    for name in ("validate", "run"):
        q = sub.add_parser(name, help=HELP[name], description=HELP[name])
        q.add_argument("--spec", required=True, help=SPEC)
        q.add_argument("--target", required=True, help=TARGET)
        q.add_argument("--gateways", help="쉼표로 구분. 기본은 대상의 모든 Gateway")
        q.add_argument("--profile", help=PROFILE)
        if name == "run":
            q.add_argument("--execute", action="store_true", help="실제로 호출한다 (없으면 보낼 호출만 보여 준다)")
            q.add_argument("--html", help="HTML 결과서를 쓸 경로 (예: report.html)")
            q.add_argument("--out", help="점검 기록(JSON)을 쓸 경로 (기본: gateprobe_out/ 아래 날짜 이름)")
            q.add_argument("--junit", help="CI 화면용 JUnit XML 경로")
            q.add_argument("--summary", help="마크다운 요약 경로")
    q = sub.add_parser("render", help=HELP["render"], description=HELP["render"])
    q.add_argument("--record", required=True, help="점검 기록(JSON)")
    q.add_argument("--html", required=True, help="HTML 결과서를 쓸 경로")
    q.add_argument("--target", help="Gateway 표시 이름(labels)을 읽을 대상 파일")
    q.add_argument("--spec", help="시나리오 제목·분류를 읽을 시나리오 파일")
    q = sub.add_parser("tools", help=HELP["tools"], description=HELP["tools"])
    q.add_argument("--target", required=True, help=TARGET)
    q.add_argument("--gateway", required=True, help="대상 파일의 Gateway 이름")
    q.add_argument("--profile", help=PROFILE)
    a = p.parse_args(argv)
    cmd = {"validate": cmd_validate, "run": cmd_run, "tools": cmd_tools, "render": cmd_render, "init": cmd_init,
           "doctor": cmd_doctor, "observe": cmd_observe, "ui": cmd_ui}[a.cmd]
    try:
        return cmd(a)
    except FileNotFoundError as exc:   # 경로 오타는 추적 정보 대신 한 줄로
        print(f"파일을 찾지 못함: {exc.filename}  (지금 폴더: {os.getcwd()})")
        return 3
    except json.JSONDecodeError as exc:
        print(f"JSON 형식 오류: {exc.msg} ({exc.lineno}번째 줄 {exc.colno}번째 글자)")
        return 3
    except ImportError as exc:   # --no-deps로 설치한 뒤 AWS 명령을 쓴 경우
        if (exc.name or "").split(".")[0] in ("boto3", "botocore"):
            print("boto3가 설치되어 있지 않다. AWS에 접속하는 명령(init, tools, run --execute)을 쓰려면 "
                  "--no-deps 없이 다시 설치한다: pip install gateprobe-<버전>-py3-none-any.whl")
            return 3
        raise
    except (RuntimeError, ValueError) as exc:   # 자격 증명·토큰 환경 변수 없음, 모르는 MCP 버전 등 (11-23 외부 예제 B에서 추적 정보로 나옴)
        print("실행 준비 실패:", str(exc)[:400])
        print("gateprobe doctor --target <대상 파일>로 무엇이 빠졌는지 확인할 수 있다")
        return 3
    except Exception as exc:
        # AWS 로그인 만료 등 botocore 오류가 추적 정보와 종료 코드 1(부적합과 같은 값)로 끝나면
        # CI에서 정책 회귀로 잘못 보인다 (11-24 시간 조건 확인 중 발견). 설정 오류 3으로 끝낸다
        if type(exc).__module__.startswith("botocore"):
            last = (str(exc).strip().splitlines() or [type(exc).__name__])[-1]
            print(f"AWS 자격 증명 또는 접속 문제로 시작하지 못했다: {last[:300]}")
            print("aws login(또는 aws sso login)으로 다시 로그인하고 --profile이 맞는지 확인한다. 정책 판정과는 무관하다")
            return 3
        raise


if __name__ == "__main__":
    sys.exit(main())
