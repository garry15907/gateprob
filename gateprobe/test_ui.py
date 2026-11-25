"""정상 확인 화면 시험 (AWS, GitHub 없이). defense-eval 폴더에서 python -m gateprobe.test_ui"""
import difflib
import http.client
import io
import json
import os
import subprocess
import tempfile
import threading
from contextlib import redirect_stdout

from gateprobe import ui_server as U
from gateprobe.ui_page import PAGE

SPEC = {"name": "s", "target": "t01-tools", "scenarios": [
    {"id": "done", "제목": "정해 둔 것", "분류": "정상 업무",
     "steps": [{"tool": "read_file", "args": {"key": "a"}, "expect": "ALLOW"}]},
    {"id": "front", "제목": "완료 문구 앞에 수치 붙이기", "요약": "읽은 뒤 앞에 수치", "분류": "유출 차단", "steps": [
        {"tool": "read_file", "args": {"key": "docs/x"}, "expect": "ALLOW"},
        {"tool": "publish_notice", "args": {"message": "통과율 94%, [T01] 완료"}, "expect": "TODO"},
        {"tool": "publish_notice", "args": {"message": "[T01] 완료"}, "wait": 2, "expect": "TODO"}]},
    {"id": "argtodo", "제목": "인자 TODO", "분류": "기타", "steps": [{"tool": "x", "args": {"a": "TODO 값"}, "expect": "TODO"}]},
    {"id": "gwdict", "제목": "Gateway별", "분류": "기타", "steps": [{"tool": "y", "args": {}, "expect": {"A": "TODO", "B": "ALLOW"}}]},
]}


def observed(spec):
    """observe가 만들었을 초안."""
    d = json.loads(json.dumps(spec))
    d["scenarios"][1]["steps"][1].update(expect="TODO", 지금결과="POLICY_DENY (정책 차단)")
    d["scenarios"][1]["steps"][2].update(expect="TODO", 지금결과="ALLOW (허용)")
    d["scenarios"][2]["steps"][0].update(expect="TODO", 지금결과="호출 안 함 (이 단계나 앞 단계의 인자에 TODO가 남음)")
    d["scenarios"][3]["steps"][0].update(expect="TODO", 지금결과="ALLOW (허용)")
    return d


FULL = {"front": {"2": {"pick": "DENY", "where": "POLICY_DENY"}, "3": {"pick": "ALLOW"}}}


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def run_tests():
    n = 0
    # 1. 화면 값 -> expect (실행기가 읽는 형식 그대로)
    assert U.to_expect("ALLOW") == "ALLOW" and U.to_expect("RECORD") is None
    assert U.to_expect("DENY", "POLICY_DENY") == "POLICY_DENY" and U.to_expect("DENY", "IAM_DENY") == "IAM_DENY"
    assert U.to_expect("DENY", "ANY") == ["IAM_DENY", "POLICY_DENY"]
    for bad in (("DENY", None), ("MAYBE", None)):
        try:
            U.to_expect(*bad)
            raise AssertionError("모르는 값을 받아들임")
        except ValueError:
            pass
    assert U.now_outcome("POLICY_DENY (정책 차단)") == "POLICY_DENY" and U.now_outcome("호출 안 함 (...)") is None
    assert U.now_outcome(None) is None
    n += 1

    # 2. 단계 세 종류: 고를 수 있음 / 잠김 / 정해 둠. 다 정한 시나리오는 숨김
    st = U.build_state(SPEC, observed(SPEC))
    assert st["issues"] == [] and st["counts"] == {"pick": 2, "locked": 2, "decided": 2}, st["counts"]
    assert st["hidden"] == 1 and [s["id"] for s in st["scenarios"]] == ["front", "argtodo", "gwdict"]
    front = st["scenarios"][0]["steps"]
    assert [x["kind"] for x in front] == ["decided", "pick", "pick"] and front[1]["now"] == "차단 (정책)"
    assert "인자" in st["scenarios"][1]["steps"][0]["why"] and "Gateway별" in st["scenarios"][2]["steps"][0]["why"]
    # 기록만(null)으로 이미 정한 단계는 observe가 다시 TODO로 적어도 정해 둠으로 본다
    sp = json.loads(json.dumps(SPEC)); sp["scenarios"][1]["steps"][2]["expect"] = None
    assert U.step_state(sp["scenarios"][1]["steps"][2], observed(SPEC)["scenarios"][1]["steps"][2])[0] == "decided"
    n += 1

    # 3. observe 뒤에 원본이 바뀌면 저장하지 않는다 (인자, 정해 둔 정상, 시나리오 목록)
    for change in (lambda s: s["scenarios"][1]["steps"][1]["args"].update(message="바뀜"),
                   lambda s: s["scenarios"][0]["steps"][0].update(expect="POLICY_DENY"),
                   lambda s: s["scenarios"].pop()):
        sp = json.loads(json.dumps(SPEC)); change(sp)
        assert U.drift(sp, observed(SPEC)), "바뀐 원본을 못 알아챔"
    # 저장 직후처럼 초안의 TODO 단계를 원본에서 정해 둔 것은 문제가 아니다 (정해 둠으로 보이고 건드리지 않음)
    saved_like = U.apply_choices(SPEC, observed(SPEC), FULL)[0]
    assert U.drift(saved_like, observed(SPEC)) == []
    assert U.build_state(saved_like, observed(SPEC))["counts"]["pick"] == 0
    n += 1

    # 4. 고른 값 적용: 안 고른 단계, 잠긴 단계 고르기
    new, missing, changed = U.apply_choices(SPEC, observed(SPEC), {"front": {"2": {"pick": "ALLOW"}}})
    assert missing == [{"id": "front", "n": 3}] and len(changed) == 1
    try:
        U.apply_choices(SPEC, observed(SPEC), {**FULL, "argtodo": {"1": {"pick": "ALLOW"}}})
        raise AssertionError("잠긴 단계를 받아들임")
    except ValueError:
        pass
    new, missing, changed = U.apply_choices(SPEC, observed(SPEC), FULL)
    assert not missing and [s["expect"] for s in new["scenarios"][1]["steps"]] == ["ALLOW", "POLICY_DENY", "ALLOW"]
    assert "지금결과" not in json.dumps(new, ensure_ascii=False) and SPEC["scenarios"][1]["steps"][1]["expect"] == "TODO"
    n += 1

    # 5. 참고용 비교: 실행기와 같은 판정
    p = U.preview(SPEC, observed(SPEC), {"front": {"2": {"pick": "DENY", "where": "IAM_DENY"}, "3": {"pick": "RECORD"}}})
    assert p["rows"] == {"front/2": "diff", "front/3": "record"} and p["diff"] == 1 and p["record"] == 1
    p = U.preview(SPEC, observed(SPEC), {"front": {"2": {"pick": "DENY", "where": "ANY"}, "3": {"pick": "DENY", "where": "POLICY_DENY"}}})
    assert p["rows"] == {"front/2": "same", "front/3": "diff"}
    n += 1

    # 6. 원본 형식 지키기: 들여쓰기 1칸 LF / 2칸 CRLF 끝 줄바꿈 없음. diff에는 expect 줄만 남는다. git 밖이면 사본을 남긴다
    for indent, nl, end in ((1, "\n", True), (2, "\r\n", False)):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            text = json.dumps(SPEC, ensure_ascii=False, indent=indent) + ("\n" if end else "")
            open(path, "wb").write(text.replace("\n", nl).encode("utf-8"))
            new, _, _ = U.apply_choices(SPEC, observed(SPEC), FULL)
            res = U.save_spec(path, new)
            raw = open(path, "rb").read()
            assert (b"\r\n" in raw) == (nl == "\r\n") and raw.endswith(nl.encode()) == end, (indent, nl, end)
            assert res["same_format"] and res["backup"] and os.path.exists(res["backup"])
            diff = [x for x in difflib.unified_diff(text.split("\n"), raw.decode("utf-8").replace("\r\n", "\n").split("\n"), lineterm="")
                    if x[:1] in "+-" and x[:3] not in ("+++", "---")]
            assert len(diff) == 4 and all('"expect"' in x for x in diff), diff
            assert [f for f in os.listdir(d) if f.endswith(".tmp")] == []
    with tempfile.TemporaryDirectory() as d:   # 한 줄짜리 JSON: 형식이 달라 diff가 커질 수 있음을 알린다
        path = os.path.join(d, "s.json")
        open(path, "w", encoding="utf-8").write(json.dumps(SPEC, ensure_ascii=False))
        assert U.save_spec(path, U.apply_choices(SPEC, observed(SPEC), FULL)[0])["same_format"] is False
    n += 1

    # 7. GitHub 주소 읽기 (사용자 정보는 버림)
    for url, want in (("https://github.com/o/r.git", "o/r"), ("https://user:tok@github.com/o/r", "o/r"),
                      ("git@github.com:o/r.git", "o/r"), ("ssh://git@github.com/o/r.git", "o/r"),
                      ("https://github.com/o/r/", "o/r"), ("https://gitlab.com/o/r.git", None), ("", None)):
        assert U.github_repo(url) == want, (url, U.github_repo(url))
    n += 1

    # 8. 올릴 명령: 한글·공백 경로의 임시 저장소. main에 직접 올리지 않고 그 파일 하나만 커밋
    with tempfile.TemporaryDirectory() as base:
        repo = os.path.join(base, "캡스톤 저장소")
        os.makedirs(os.path.join(repo, "checks"))
        git(repo, "init", "-q", "-b", "main")
        path = os.path.join(repo, "checks", "spec core.json")
        open(path, "w", encoding="utf-8").write(json.dumps(SPEC, ensure_ascii=False, indent=1) + "\n")
        open(os.path.join(repo, "other.txt"), "w").write("a")
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "init")
        git(repo, "remote", "add", "origin", "https://user:secret@github.com/o/r.git")
        assert U.save_spec(path, U.apply_choices(SPEC, observed(SPEC), FULL)[0])["backup"] is None   # git이 관리하면 사본 없음
        assert not any("다른 변경" in w for w in U.git_plan(path, ["front"])["warnings"])   # 저장한 그 파일만 바뀜
        open(os.path.join(repo, "other.txt"), "w").write("b")
        from datetime import datetime
        g = U.git_plan(path, ["front", "x\"; rm -rf /"], now=datetime(2026, 11, 25, 10, 30, 0))
        assert g["ok"] and g["branch"] == "gateprobe/expect-20261125-103000" and g["file"] == "checks/spec core.json"
        assert all(c.startswith('git -C "') for c in g["commands"]), g["commands"]   # cd 대신 -C (드라이브가 달라도 됨)
        assert [c.split('" ', 1)[1] for c in g["commands"]] == [
            'switch -c "gateprobe/expect-20261125-103000"', 'add "checks/spec core.json"',
            'commit -m "정상 확인: front, xrm-rf" "checks/spec core.json"',
            'push -u origin "gateprobe/expect-20261125-103000"'], g["commands"]
        assert g["back"].endswith('switch "main"')
        assert g["pr_url"] == "https://github.com/o/r/compare/main...gateprobe%2Fexpect-20261125-103000?expand=1"
        assert "secret" not in json.dumps(g) and any("다른 변경 파일 1개" in w for w in g["warnings"])
        assert any("GitHub에 없다" in w for w in g["warnings"])   # origin/main을 받아 온 적 없음
        git(repo, "checkout", "-q", "--detach")
        assert not U.git_plan(path, ["front"])["ok"]
    with tempfile.TemporaryDirectory() as base:   # 저장소 밖
        path = os.path.join(base, "s.json"); open(path, "w").write("{}")
        assert not U.git_plan(path, ["a"])["ok"]
    with tempfile.TemporaryDirectory() as base:   # .gitignore 대상
        git(base, "init", "-q", "-b", "main")
        open(os.path.join(base, ".gitignore"), "w").write("*.json\n")
        path = os.path.join(base, "s.json"); open(path, "w").write("{}")
        g = U.git_plan(path, ["a"])
        assert not g["ok"] and "gitignore" in g["reason"], g
    n += 1

    # 9. 서버: 토큰, Host, Origin, JSON만, 크기 상한, 저장 흐름
    with tempfile.TemporaryDirectory() as d:
        sp, dp = os.path.join(d, "s.json"), os.path.join(d, "s_observed.json")
        json.dump(SPEC, open(sp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        json.dump(observed(SPEC), open(dp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        app = U.App(sp, dp)
        srv = U.make_server(app, 0)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()

        def req(method, path, body=None, host=None, token=True, ctype="application/json", origin=None, length=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            data = json.dumps(body).encode() if body is not None else None
            h = {"Host": host or f"127.0.0.1:{port}"}
            if token:
                h["X-Gateprobe-Token"] = app.token if token is True else token
            if data is not None:
                h["Content-Type"] = ctype
                h["Content-Length"] = str(length if length is not None else len(data))
            if origin:
                h["Origin"] = origin
            c.request(method, path, body=data if length is None else b"", headers=h)
            r = c.getresponse()
            out = (r.status, r.getheader("Content-Security-Policy"), r.read().decode("utf-8"))
            c.close()
            return out
        try:
            code, csp, body = req("GET", "/", token=False)
            assert code == 200 and app.nonce in csp and f'nonce="{app.nonce}"' in body and "정상 확인" in body
            assert req("GET", "/api/state", token=False)[0] == 403 and req("GET", "/api/state", token="x" * 43)[0] == 403
            code, _, body = req("GET", "/api/state")
            assert code == 200 and json.loads(body)["counts"]["pick"] == 2
            assert req("GET", "/api/state", host="evil.example")[0] == 403
            assert req("GET", "/api/state", host=f"localhost:{port}")[0] == 200
            assert req("POST", "/api/preview", {"choices": {}}, ctype="text/plain")[0] == 415
            assert req("POST", "/api/preview", {"choices": {}}, origin="http://evil.example")[0] == 403
            assert req("POST", "/api/preview", {"choices": {}}, length=2_000_000)[0] == 413
            assert req("POST", "/api/save", {"choices": {**FULL, "argtodo": {"1": {"pick": "ALLOW"}}}})[0] == 400
            code, _, body = req("POST", "/api/save", {"choices": {"front": {"2": {"pick": "ALLOW"}}}})
            assert code == 200 and json.loads(body)["saved"] is False and json.loads(body)["missing"]
            code, _, body = req("POST", "/api/save", {"choices": FULL})
            r = json.loads(body)
            assert code == 200 and r["saved"] and r["changed"] == 2 and r["locked"] == 2, r
            assert any("TODO" in e for e in r["errors"]) and r["git"] is None   # 잠긴 단계가 남아 올릴 명령은 없음
            saved = json.load(open(sp, encoding="utf-8"))
            assert saved["scenarios"][1]["steps"][1]["expect"] == "POLICY_DENY"
            assert json.loads(req("GET", "/api/state")[2])["counts"]["pick"] == 0
        finally:
            srv.shutdown(); srv.server_close()
    n += 1

    # 10. 화면은 파일 내용을 textContent로만 넣는다. 명령줄 안내
    assert "innerHTML" not in PAGE and "outerHTML" not in PAGE and "insertAdjacentHTML" not in PAGE
    from gateprobe.__main__ import main as cli
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "s.json"); json.dump(SPEC, open(sp, "w", encoding="utf-8"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert cli(["ui", "--spec", sp]) == 3                       # 초안 없음
            assert cli(["ui", "--spec", sp, "--draft", sp]) == 3        # 원본과 같음
            assert cli(["ui", "--spec", os.path.join(d, "x.json")]) == 3
        assert "observe" in buf.getvalue()
    n += 1
    # 11. 검토(11-24) 반영: 도구 오류는 잠금, 화면을 연 뒤 원본이 바뀌면 거부, 커밋 안 된 수정은 사본과 경고,
    #     경로의 셸 특수 문자, 한글·숫자 id와 긴 커밋 메시지
    d = observed(SPEC); d["scenarios"][1]["steps"][2]["지금결과"] = "TOOL_ERROR (도구 오류)"
    assert U.step_state(SPEC["scenarios"][1]["steps"][2], d["scenarios"][1]["steps"][2])[0] == "locked"
    with tempfile.TemporaryDirectory() as dd:
        path = os.path.join(dd, "s.json"); json.dump(SPEC, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        other = json.loads(json.dumps(SPEC)); other["name"] = "다른 편집기가 바꿈"
        try:
            U.save_spec(path, U.apply_choices(SPEC, observed(SPEC), FULL)[0], expected=other)
            raise AssertionError("바뀐 원본을 덮어씀")
        except ValueError:
            pass
        assert json.load(open(path, encoding="utf-8")) == SPEC
    with tempfile.TemporaryDirectory() as base:
        repo = os.path.join(base, "r")
        os.makedirs(repo); git(repo, "init", "-q", "-b", "main")
        path = os.path.join(repo, "s.json"); json.dump(SPEC, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "init")
        git(repo, "remote", "add", "origin", "git@github.com:o/r.git")
        sp = json.loads(json.dumps(SPEC)); sp["name"] = "커밋 안 한 수정"
        json.dump(sp, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        res = U.save_spec(path, U.apply_choices(sp, observed(sp), FULL)[0])
        assert res["dirty_before"] and res["backup"] and os.path.exists(res["backup"])
        g = U.git_plan(path, ["front"], dirty_before=True)
        assert any("커밋하지 않은 수정" in w for w in g["warnings"])
        g = U.git_plan(path, ["유출_차단", 7] + [f"scenario_{i:02d}" for i in range(20)])
        msg = g["commands"][2].split('-m "', 1)[1].split('"', 1)[0]
        assert msg.startswith("정상 확인: 유출_차단, 7, scenario_00") and len(msg) <= 160 and msg.endswith("개"), msg
    with tempfile.TemporaryDirectory() as base:
        repo = os.path.join(base, "a$b")
        os.makedirs(repo); git(repo, "init", "-q", "-b", "main")
        path = os.path.join(repo, "s.json"); open(path, "w").write("{}")
        git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "init")
        git(repo, "remote", "add", "origin", "https://github.com/o/r.git")
        g = U.git_plan(path, ["a"])
        assert not g["ok"] and "$" in g["reason"], g
    n += 1
    print(f"정상 확인 화면 시험 통과 ({n}개)")


if __name__ == "__main__":
    run_tests()
