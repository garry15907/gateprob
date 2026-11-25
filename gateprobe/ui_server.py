"""정상 확인 화면 (gateprobe ui).

observe 초안의 '지금 결과'를 보면서 사람이 단계마다 정상을 고르고, 원본 시나리오에서 그 단계의 expect만 바꿔 저장한다.
화면은 정상을 대신 정하지 않는다. 정상 칸은 비워 두고 지금 결과는 참고로만 보여 준다 (계획 2판, 독립 검토 11-24).

서버는 127.0.0.1에만 열고, 실행마다 만든 토큰이 있어야 데이터를 주고받는다. AWS에는 접속하지 않는다.
저장한 뒤 사람이 'GitHub에 올리기'를 누르면 새 브랜치에 그 파일 하나만 커밋해 push하고 PR 만들기 페이지를 연다 (0.6.0, 사용자 요청 11-25).
main에 직접 올리거나 강제로 올리지 않고, PR을 만들거나 병합하는 일은 사람이 GitHub에서 한다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit

from gateprobe.classify import OUTCOMES
from gateprobe.spec import Target, expectation, matches, validate

MAX_BODY = 1_000_000
WHERE = {"POLICY_DENY": "POLICY_DENY", "IAM_DENY": "IAM_DENY", "ANY": ["IAM_DENY", "POLICY_DENY"]}
NOW_KO = {"ALLOW": "허용", "POLICY_DENY": "차단 (정책)", "IAM_DENY": "차단 (권한)", "TOOL_ERROR": "도구 오류",
          "UNKNOWN": "판정 불가"}


def _has_todo(x):
    return "TODO" in json.dumps(x, ensure_ascii=False)


# ---------- 시나리오 다루기 (서버 없이 시험할 수 있게 순수 함수로) ----------

def now_outcome(text):
    """observe가 적은 지금결과 'POLICY_DENY (정책 차단)' -> 'POLICY_DENY'. 결과 이름으로 시작하지 않으면 None."""
    if not isinstance(text, str):
        return None
    head = text.strip().split(" ", 1)[0]
    return head if head in OUTCOMES else None


def expect_words(expect):
    """정해 둔 정상을 화면 말로."""
    if expect is None:
        return "기록만 (검사 안 함)"
    if expect == "ALLOW":
        return "허용"
    if expect == "POLICY_DENY":
        return "차단 (정책)"
    if expect == "IAM_DENY":
        return "차단 (권한)"
    if isinstance(expect, list) and all(isinstance(x, str) for x in expect) and sorted(expect) == ["IAM_DENY", "POLICY_DENY"]:
        return "차단 (어디서든)"
    if isinstance(expect, dict) and "outcome" not in expect:
        return "Gateway마다 다름 (파일에서 편집)"
    return "고급 정상 (파일에서 편집): " + json.dumps(expect, ensure_ascii=False)[:80]


def to_expect(pick, where=None):
    """화면에서 고른 값 -> 파일의 expect. 실행기(run)가 지금 읽는 형식 그대로다."""
    if pick == "ALLOW":
        return "ALLOW"
    if pick == "RECORD":
        return None
    if pick == "DENY":
        if where not in WHERE:
            raise ValueError(f"차단 위치를 모른다: {where!r}")
        return WHERE[where]
    raise ValueError(f"고른 값을 모른다: {pick!r}")


def step_state(orig, dstep):
    """원본 단계와 초안 단계로 ('pick' | 'locked' | 'decided', 설명)을 정한다."""
    if "expect" in orig and (orig["expect"] is None or not _has_todo(orig["expect"])):
        return "decided", expect_words(orig["expect"])
    if orig.get("expect") not in (None, "TODO"):
        return "locked", "원본의 정상이 목록이나 Gateway별 형식 안에 TODO가 있다. 파일에서 직접 정한다"
    if dstep.get("expect") != "TODO":
        return "locked", "초안에 이 단계의 지금 결과가 없다. observe를 다시 돌린다"
    now = dstep.get("지금결과")
    if now_outcome(now) in ("TOOL_ERROR", "UNKNOWN"):
        return "locked", ("지금 결과가 도구 오류나 판정 불가다. 원인을 확인하고 파일에서 정한다 "
                          "(업무 오류가 정상이면 TOOL_ERROR)")
    if now_outcome(now):
        return "pick", ""
    if isinstance(now, str) and now.startswith("호출 안 함"):
        why = now[len("호출 안 함"):].strip(" ()") or "이유 모름"
        return "locked", f"observe가 이 단계를 호출하지 못했다 ({why}). 원인을 고친 뒤 observe를 다시 돌린다"
    return "locked", "지금 결과가 없다. observe를 다시 돌린다"


def _strip(step, ignore_expect):
    return {k: v for k, v in step.items() if k != "지금결과" and not (ignore_expect and k == "expect")}


def drift(spec, draft):
    """초안이 지금 원본에서 만든 것인지 본다. expect와 지금결과 말고 다른 곳이 다르면 그 위치 목록.
    observe 뒤에 원본을 고쳤는데 초안 기준으로 저장하면 그 고친 내용이 사라지기 때문이다 (검토 B2)."""
    out = []
    if {k: v for k, v in spec.items() if k != "scenarios"} != {k: v for k, v in draft.items() if k != "scenarios"}:
        out.append("시나리오 파일 머리 (이름, 대상, 사전 객체 등)")
    ss, ds = spec.get("scenarios", []), draft.get("scenarios", [])
    if [s.get("id") for s in ss] != [d.get("id") for d in ds]:
        return out + ["시나리오 목록이나 순서"]
    for s, d in zip(ss, ds):
        if {k: v for k, v in s.items() if k != "steps"} != {k: v for k, v in d.items() if k != "steps"}:
            out.append(f"{s['id']}: 제목, 요약, 설명")
        a_steps, b_steps = s.get("steps", []), d.get("steps", [])
        if len(a_steps) != len(b_steps):
            out.append(f"{s['id']}: 단계 수")
            continue
        for i, (a, b) in enumerate(zip(a_steps, b_steps), 1):
            # 초안이 TODO인 단계는 정상 칸을 비교하지 않는다. 원본에서 이미 정했으면(저장 직후 포함) 화면이 '정해 둠'으로
            # 보여 주고 건드리지 않으므로 잃는 것이 없다
            draft_todo = b.get("expect") == "TODO"
            if _strip(a, draft_todo) != _strip(b, draft_todo):
                out.append(f"{s['id']} {i}단계")
    return out


def build_state(spec, draft):
    issues = drift(spec, draft)
    scenarios, counts, hidden = [], {"pick": 0, "locked": 0, "decided": 0}, 0
    if not issues:
        for s, d in zip(spec.get("scenarios", []), draft.get("scenarios", [])):
            steps = []
            for i, (st, dst) in enumerate(zip(s.get("steps", []), d.get("steps", [])), 1):
                kind, why = step_state(st, dst)
                counts[kind] += 1
                now = dst.get("지금결과")
                steps.append({"n": i, "tool": st.get("tool"), "args": st.get("args", {}), "wait": st.get("wait"),
                              "kind": kind, "why": why, "now": NOW_KO.get(now_outcome(now)) if now_outcome(now) else now})
            if any(x["kind"] != "decided" for x in steps):
                scenarios.append({"id": s.get("id"), "title": s.get("제목") or s.get("id"), "group": s.get("분류"),
                                  "summary": s.get("요약") or s.get("설명"), "steps": steps})
            else:
                hidden += 1
    return {"issues": issues, "scenarios": scenarios, "counts": counts, "hidden": hidden}


def _pairs(spec, draft):
    for s, d in zip(spec.get("scenarios", []), draft.get("scenarios", [])):
        for i, (st, dst) in enumerate(zip(s.get("steps", []), d.get("steps", [])), 1):
            yield s, i, st, dst


def apply_choices(spec, draft, choices):
    """원본 사본에서 고를 수 있는 단계의 expect만 바꾼다. choices: {"시나리오 id": {"단계 번호": {"pick", "where"}}}.
    반환: (새 시나리오, 안 고른 단계 목록, 바꾼 단계 목록)."""
    new = json.loads(json.dumps(spec))
    missing, changed = [], []
    for s, i, st, dst in _pairs(new, draft):
        kind, _ = step_state(st, dst)
        c = (choices.get(s["id"]) or {}).get(str(i))
        if kind != "pick":
            if c:
                raise ValueError(f"{s['id']} {i}단계는 화면에서 정할 수 없는 단계다")
            continue
        if not c or not c.get("pick"):
            missing.append({"id": s["id"], "n": i})
            continue
        st["expect"] = to_expect(c["pick"], c.get("where"))
        changed.append({"id": s["id"], "n": i})
    return new, missing, changed


def preview(spec, draft, choices):
    """참고용 비교: 고른 정상과 observe가 한 번 본 결과. 실행기와 같은 expectation/matches로 판정한다."""
    rows, n = {}, {"same": 0, "diff": 0, "unknown": 0, "record": 0}
    for s, i, st, dst in _pairs(spec, draft):
        c = (choices.get(s["id"]) or {}).get(str(i))
        if step_state(st, dst)[0] != "pick" or not c or not c.get("pick"):
            continue
        try:
            exp = to_expect(c["pick"], c.get("where"))
        except ValueError:
            continue
        now = now_outcome(dst.get("지금결과"))
        if exp is None:
            k = "record"
        elif now is None:
            k = "unknown"
        else:
            k = "same" if matches(expectation(exp, "*"), now, None) else "diff"
        rows[f"{s['id']}/{i}"] = k
        n[k] += 1
    return {"rows": rows, **n}


# ---------- 원본 형식을 지키며 저장 ----------

def detect_format(raw: bytes):
    text = raw.decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    indent = 2
    for line in text.replace("\r\n", "\n").split("\n")[1:]:
        m = re.match(r"^([ \t]+)\S", line)
        if m:
            indent = m.group(1) if m.group(1).startswith("\t") else len(m.group(1))
            break
    return {"newline": nl, "indent": indent, "end_newline": text.endswith("\n"),
            "ensure_ascii": raw.isascii() and "\\u" in text}


def dumps_like(obj, fmt):
    s = json.dumps(obj, ensure_ascii=fmt["ensure_ascii"], indent=fmt["indent"])
    if fmt["end_newline"]:
        s += "\n"
    return s.replace("\n", fmt["newline"])


def _git(cwd, *args, timeout=15):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    p = subprocess.run(["git", "-c", "core.quotepath=false", *args], cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout.rstrip(), p.stderr.strip()   # 앞 공백은 남긴다 (status 형식의 일부)


def _git_tracked(path):
    try:
        return _git(os.path.dirname(os.path.abspath(path)), "--literal-pathspecs", "ls-files", "--error-unmatch", "--",
                    os.path.basename(path))[0] == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _git_dirty(path):
    """git이 추적하는 파일에 커밋하지 않은 수정이 있는지."""
    try:
        return _git(os.path.dirname(os.path.abspath(path)), "--literal-pathspecs", "diff", "--quiet", "HEAD", "--",
                    os.path.basename(path))[0] == 1
    except (OSError, subprocess.SubprocessError):
        return False


def _replace(src, dst, tries=6):
    """Windows에서 다른 프로그램(편집기, 백신, OneDrive)이 잠깐 잡고 있으면 교체가 실패한다. 짧게 다시 시도 (검토 B3)."""
    for i in range(tries):
        try:
            return os.replace(src, dst)
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.2 * (i + 1))


def _backup_path(spec_path):
    """저장 전 사본 경로. 저장소 안이면 .git/gateprobe-backup 아래에 둬서 git add -A에 딸려 가지 않게 한다 (검토 11-25)."""
    stamp = f"{datetime.now():%Y%m%d-%H%M%S-%f}"
    try:
        rc, gd, _ = _git(os.path.dirname(os.path.abspath(spec_path)), "rev-parse", "--absolute-git-dir")
    except (OSError, subprocess.SubprocessError):
        rc, gd = 1, ""
    if rc == 0 and gd:
        folder = os.path.join(os.path.normpath(gd), "gateprobe-backup")
        os.makedirs(folder, exist_ok=True)
        return os.path.join(folder, f"{os.path.basename(spec_path)}.{stamp}.bak")
    return f"{spec_path}.{stamp}.bak"


def save_spec(spec_path, new_spec, target=None, expected=None):
    """같은 폴더의 임시 파일에 쓰고 바꿔 넣는다. expected를 주면 지금 파일 내용이 그것과 같을 때만 쓴다
    (읽은 뒤 다른 편집기가 바꾼 것을 덮지 않으려고, 검토 B2). git이 추적하지 않거나 커밋 안 된 수정이 있으면 사본을 먼저 남긴다."""
    with open(spec_path, "rb") as f:
        raw = f.read()
    fmt = detect_format(raw)
    old = raw.decode("utf-8")
    if expected is not None and json.loads(old) != expected:
        raise ValueError("화면을 연 뒤 원본 파일이 바뀌었다. 화면을 새로 고친 뒤 다시 고른다")
    same_format = dumps_like(json.loads(old), fmt) == old
    tracked = _git_tracked(spec_path)
    dirty = tracked and _git_dirty(spec_path)
    backup = None
    if not tracked or dirty:
        backup = _backup_path(spec_path)
        shutil.copyfile(spec_path, backup)
    fd, tmp = tempfile.mkstemp(prefix=".gateprobe-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(spec_path)))
    try:
        data = dumps_like(new_spec, fmt).encode("utf-8")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _replace(tmp, spec_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {"same_format": same_format, "backup": backup, "dirty_before": dirty, "errors": validate(new_spec, target),
            "sha": hashlib.sha256(data).hexdigest()}


# ---------- GitHub에 올리기 ----------

def github_repo(url):
    """https, ssh 형태의 GitHub 원격 주소 -> 'owner/repo'. 주소 안의 사용자 정보는 버린다."""
    m = re.match(r"^(?:https?://(?:[^@/\s]+@)?github\.com/|ssh://(?:[^@/\s]+@)?github\.com(?::\d+)?/|[^@\s/]+@github\.com:)"
                 r"([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", (url or "").strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _safe(text):
    """커밋 메시지에 넣을 id. 따옴표 안에서 셸이 풀 수 있는 글자는 뺀다 (한글은 남김)."""
    return re.sub(r"[^\w.-]", "", str(text))


def git_plan(spec_path, scenario_ids, now=None, dirty_before=False):
    d = os.path.dirname(os.path.abspath(spec_path))
    try:
        rc, top, _ = _git(d, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "reason": "git을 실행하지 못했습니다. 파일을 직접 저장소에 올리세요"}
    if rc:
        return {"ok": False, "reason": "이 파일은 git 저장소 안에 있지 않습니다. 저장소 안의 파일로 화면을 다시 열거나 직접 올리세요"}
    top = os.path.normpath(top)
    try:
        rel = os.path.relpath(os.path.realpath(spec_path), os.path.realpath(top)).replace("\\", "/")
    except ValueError:   # 드라이브가 다름 (subst 드라이브 등)
        rel = ".."
    if rel.startswith(".."):
        return {"ok": False, "reason": "저장소 경로를 확정하지 못했습니다(다른 드라이브나 링크). 저장소 폴더에서 직접 올리세요"}
    bad = sorted(set(re.sub(r"[\w .\-/\\:()~+,@\[\]#]", "", top + rel)))   # 허용 글자만 (PowerShell은 “ ”도 따옴표, 검토 11-25)
    if bad:
        return {"ok": False, "reason": f"경로에 명령에 넣기 어려운 글자({' '.join(bad)})가 있어 명령을 안전하게 만들 수 없습니다. 직접 올리세요"}
    if _git(top, "check-ignore", "-q", rel)[0] == 0:
        return {"ok": False, "reason": f"{rel} 파일은 .gitignore 대상이라 올릴 수 없습니다"}
    if _git(top, "rev-parse", "--verify", "--quiet", "HEAD")[0]:
        return {"ok": False, "reason": "커밋이 하나도 없는 저장소입니다. 첫 커밋을 만든 뒤 터미널에서 직접 올리세요"}
    rc, branch, _ = _git(top, "rev-parse", "--abbrev-ref", "HEAD")
    if rc or branch == "HEAD":
        return {"ok": False, "reason": "지금 브랜치가 없습니다(detached HEAD). 터미널에서 원래 브랜치로 돌아간 뒤 직접 커밋해 올리세요"}
    warnings = []
    rc, url, _ = _git(top, "remote", "get-url", "origin")
    repo = github_repo(url) if rc == 0 else None
    if rc:
        return {"ok": False, "reason": "origin 원격 저장소가 없습니다. GitHub 저장소를 origin으로 연결한 뒤 터미널에서 직접 올리세요"}
    if not repo:
        warnings.append("origin이 GitHub 주소가 아닙니다. 올리기까지만 하니, PR은 그 서비스에서 만드세요")
    rc, status, _ = _git(top, "status", "--porcelain", "-z", "--untracked-files=no")
    entries, others = status.split("\0"), []
    k = 0
    while k < len(entries):   # -z 형식: "XY 경로", 이름 바꾸기는 다음 칸에 원래 경로가 하나 더 온다
        e = entries[k]
        if len(e) > 3:
            if e[3:] != rel:
                others.append(e[3:])
            if e[0] in "RC":
                k += 1
        k += 1
    if others:
        warnings.append(f"다른 변경 파일 {len(others)}개가 있습니다. 이번 커밋에는 {rel} 하나만 들어갑니다")
    if dirty_before:
        warnings.append(f"{rel}에 이 화면에서 저장하기 전부터 커밋하지 않은 수정이 있었습니다. 그 수정도 이번 커밋에 들어갑니다 "
                        f"(저장 전 파일은 .bak으로 남김)")
    rc, ahead, _ = _git(top, "rev-list", "--count", f"origin/{branch}..HEAD")
    if rc:
        warnings.append(f"원래 브랜치({branch})가 GitHub에 없습니다. PR 페이지가 열리지 않으면 GitHub에서 기준 브랜치를 골라 PR을 만드세요")
    elif ahead.isdigit() and int(ahead):
        warnings.append(f"원래 브랜치({branch})에 아직 GitHub에 올리지 않은 커밋 {ahead}개가 있습니다. 이 커밋들도 PR에 같이 들어갑니다")
    if branch.startswith(("gateprobe/expect-", "gateprobe-expect-")):
        warnings.append(f"지금 브랜치({branch})는 앞서 올린 정상 확인 브랜치입니다. 이대로 올리면 PR이 main이 아니라 이 브랜치를 "
                        "향합니다. 보통은 원래 브랜치로 돌아간 뒤 화면을 다시 엽니다")
    else:
        rc, default, _ = _git(top, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
        if rc == 0 and default and default != f"origin/{branch}":
            warnings.append(f"PR은 지금 브랜치({branch})에 합치는 요청으로 열립니다. GitHub 기본 브랜치"
                            f"({default.split('/', 1)[-1]})가 아니어서, CI가 기본 브랜치 PR에서만 돈다면 점검하지 않을 수 있습니다")
    if _git(top, "var", "GIT_COMMITTER_IDENT")[0]:
        warnings.append(IDENT_HINT)
    prefix = "gateprobe/expect"
    if _git(top, "rev-parse", "--verify", "--quiet", "refs/heads/gateprobe")[0] == 0:
        prefix = "gateprobe-expect"   # 'gateprobe' 브랜치가 있으면 'gateprobe/...'를 만들 수 없다
    new_branch = f"{prefix}-{(now or datetime.now()):%Y%m%d-%H%M%S}"
    ids, msg = [x for x in (_safe(i) for i in scenario_ids) if x], "정상 확인"
    for i, x in enumerate(ids):   # 150자를 넘기면 id 중간이 아니라 경계에서 자른다
        nxt = msg + (": " if i == 0 else ", ") + x
        if len(nxt) > 150:
            msg += f" 외 {len(ids) - i}개"
            break
        msg = nxt
    g = f'git -C "{top}"'   # cd 대신: cmd에서 드라이브가 달라도 된다 (검토 B6)
    commands = [f'{g} switch -c "{new_branch}"', f'{g} add "{rel}"', f'{g} commit -m "{msg}" "{rel}"',
                f'{g} push -u origin "{new_branch}"']
    body = (f"gateprobe 정상 확인 화면에서 사람이 정한 정상을 저장했습니다.\n\n바뀐 파일: {rel}\n시나리오: {', '.join(ids) or '-'}\n\n"
            "PR을 만들면 CI가 새로 정한 정상으로 지금 정책을 점검합니다. 정상이 바뀐 줄은 Files changed에서 확인하세요.")
    pr_url = (f"https://github.com/{repo}/compare/{quote(branch, safe='')}...{quote(new_branch, safe='')}?expand=1"
              f"&title={quote(msg, safe='')}&body={quote(body, safe='')}" if repo else None)
    return {"ok": True, "commands": commands, "pr_url": pr_url, "branch": new_branch, "base": branch, "file": rel,
            "back": f'{g} switch "{branch}"', "warnings": warnings, "top": top, "message": msg}


def _scrub(text):
    """git 출력에 섞일 수 있는 주소 속 사용자 정보와 토큰을 지운다."""
    return re.sub(r"(https?://)[^@\s/]+@", r"\1", text or "", flags=re.I)


def _why(out, err):
    """git이 실패한 까닭 한 줄. fatal:, error: 줄을 먼저 고르고, 끝 마침표는 뗀다."""
    lines = [x.strip() for x in ((err or "") + "\n" + (out or "")).splitlines() if x.strip()]
    pick = next((x for x in lines if x.startswith(("fatal:", "error:"))), lines[-1] if lines else "알 수 없는 오류")
    return _scrub(pick).rstrip(".")[:300]


IDENT_HINT = ('git 사용자 이름과 메일이 정해져 있지 않아 커밋할 수 없습니다. 터미널에서 git config --global user.name "이름"과 '
              'git config --global user.email "메일"을 실행하세요')


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _kill_tree(p):
    """Windows에서는 git만 끝내면 로그인 도우미(GCM), ssh 같은 자식이 남아 출력을 붙잡는다. 자식까지 끝낸다."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True, timeout=15)
        else:
            p.kill()
    except (OSError, subprocess.SubprocessError):
        p.kill()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def _run_git(cwd, args, timeout):
    """올리기용 git 실행. 입력은 막고, 출력은 파이프 대신 임시 파일로 받고, 시간이 넘으면 자식까지 끝낸다 (검토 11-25).
    반환 (rc, out, err). 시간이 넘으면 rc는 None."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if "GIT_SSH_COMMAND" not in env and _git(cwd, "config", "--get", "core.sshCommand")[0]:
        env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"   # ssh가 터미널에서 암호 문구를 기다리며 멈추지 않게
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(["git", "-c", "core.quotepath=false", "--literal-pathspecs", *args], cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=out, stderr=err, env=env)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(p)
            rc = None
        out.seek(0)
        err.seek(0)
        return (rc, out.read().decode("utf-8", "replace").rstrip(), err.read().decode("utf-8", "replace").strip())


def push_plan(plan, step_timeout=60, push_timeout=300):
    """저장할 때 만든 계획대로 새 브랜치 만들기, 그 파일 하나만 커밋, push를 대신 한다 (0.6.0).
    저장할 때의 브랜치에 그대로 있고, 파일이 저장한 그대로이고, 커밋할 수 있고, 같은 이름의 브랜치가 없을 때만 한다.
    main에 직접 올리거나 강제로 올리지 않는다. 커밋 전에 실패하면 원래 브랜치로 되돌린다.
    반환: {"ok", "reason", "next"(이어서 칠 명령), "back"(돌아가는 명령), "moved"(이 컴퓨터가 새 브랜치에 남았는지)}"""
    top, rel, base, br, msg = plan["top"], plan["file"], plan["base"], plan["branch"], plan["message"]
    g = f'git -C "{top}"'
    back = plan.get("back") or f'{g} switch "{base}"'
    nxt = f'{g} push -u origin "{br}"'

    def fail(reason, nxt=None, moved=False):
        return {"ok": False, "reason": reason, "next": nxt, "back": back if moved else None, "moved": moved}

    def has_branch():
        return _git(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{br}")[0] == 0

    def committed():
        a, b = _git(top, "rev-parse", "--verify", "--quiet", br), _git(top, "rev-parse", "--verify", "--quiet", base)
        return a[0] == 0 and b[0] == 0 and a[1] != b[1]

    def undo():
        """원래 브랜치로 돌아가고 새 브랜치를 지운다. 저장한 파일 내용은 그대로 둔다."""
        _git(top, "--literal-pathspecs", "restore", "--staged", "--", rel)
        if _git(top, "rev-parse", "--abbrev-ref", "HEAD")[1] != base:
            _git(top, "switch", base)
        if has_branch():
            _git(top, "branch", "-D", br)
        now = _git(top, "rev-parse", "--abbrev-ref", "HEAD")[1]
        return now == base and not has_branch(), now

    rc, cur, _ = _git(top, "rev-parse", "--abbrev-ref", "HEAD")
    if rc or cur != base:
        return fail(f"지금 브랜치({cur})가 저장할 때의 브랜치({base})와 달라 올리지 않았습니다. 터미널에서 직접 올리세요")
    path = os.path.join(top, rel)
    if plan.get("sha") and (not os.path.exists(path) or _sha(path) != plan["sha"]):
        return fail("저장한 뒤 파일이 바뀌어 올리지 않았습니다. 바뀐 내용은 형식 검사를 거치지 않았습니다. "
                    "gateprobe validate로 검사한 뒤 터미널에서 직접 올리세요")
    if _git(top, "var", "GIT_COMMITTER_IDENT")[0]:
        return fail(IDENT_HINT + ". 그런 다음 다시 누르세요")
    if has_branch():
        return fail(f"같은 이름의 브랜치({br})가 이미 있어 올리지 않았습니다. 터미널에서 직접 올리세요")
    if (_git(top, "--literal-pathspecs", "diff", "--quiet", "HEAD", "--", rel)[0] == 0
            and _git(top, "--literal-pathspecs", "ls-files", "--error-unmatch", "--", rel)[0] == 0):
        return fail("올릴 변경이 없습니다. 저장한 파일이 마지막 커밋과 같습니다")
    for args, what in ((["switch", "-c", br], "새 브랜치를 만들지"), (["add", "--", rel], "파일을 추가하지"),
                       (["commit", "-m", msg, "--", rel], "커밋하지")):
        t0 = time.time()
        rc, out, err = _run_git(top, args, step_timeout)
        if rc == 0:
            continue
        if rc is None:   # 우리가 끝낸 git이 남긴 잠금 파일만 지운다 (이 단계를 시작한 뒤에 생긴 것)
            gd = _git(top, "rev-parse", "--absolute-git-dir")[1]
            lock = os.path.join(os.path.normpath(gd), "index.lock") if gd else ""
            try:
                if lock and os.path.getmtime(lock) >= t0 - 1:
                    os.remove(lock)
            except OSError:
                pass
        if args[0] == "commit" and committed():   # 시간 초과 직전에 커밋은 끝났다
            break
        why = "제한 시간 안에 끝나지 않음" if rc is None else _why(out, err)
        hint = ". " + IDENT_HINT if re.search(r"identity|auto-detect|user\.name|user\.email", why, re.I) else ""
        ok, now = undo()
        if ok:
            return fail(f"{what} 못했습니다(git 메시지: {why}). 새 브랜치는 지우고 원래 브랜치({base})로 돌아왔습니다. "
                        f"저장한 파일은 그대로 있습니다{hint}")
        return fail(f"{what} 못했습니다(git 메시지: {why}). 원래 브랜치로 되돌리지도 못해 이 컴퓨터는 지금 브랜치({now})에 있습니다. "
                    "편집기 같은 다른 프로그램이 저장소를 쓰고 있는지 확인한 뒤 터미널에서 git status로 상태를 보세요", moved=True)
    rc, out, err = _run_git(top, ["push", "-u", "origin", br], push_timeout)
    where = f"커밋은 새 브랜치({br})에 있고, 이 컴퓨터도 그 브랜치에 있습니다"
    if rc is None:
        return fail(f"{push_timeout // 60}분 안에 GitHub에 올리기가 끝나지 않았습니다. {where}. 로그인 창이 떠 있었다면 로그인한 뒤 "
                    "터미널에서 아래 명령으로 이어서 올리세요", nxt, moved=True)
    if rc:
        return fail(f"GitHub에 올리지 못했습니다(git 메시지: {_why(out, err)}). 대개 로그인이나 저장소 쓰기 권한 문제입니다. "
                    f"{where}. 로그인을 확인한 뒤 터미널에서 아래 명령을 실행하세요", nxt, moved=True)
    return {"ok": True, "branch": br, "base": base, "pr_url": plan.get("pr_url"), "back": back, "moved": True}


# ---------- 서버 ----------

class App:
    def __init__(self, spec_path, draft_path, target_path=None):
        self.spec_path, self.draft_path, self.target_path = spec_path, draft_path, target_path
        self.token, self.nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(16)
        self.lock = threading.Lock()
        self.plan = None   # 마지막 저장 때 만든 올리기 계획. 올리기는 화면이 보낸 명령이 아니라 이것만 실행한다
        self.pushing = False
        self.open_browser = True

    def push(self):
        """올리기는 몇 분 걸릴 수 있어(로그인 창) 잠금 밖에서 한다. 그동안 화면 읽기는 되고 저장과 두 번째 올리기는 거부한다."""
        with self.lock:
            if self.pushing:
                raise ValueError("이미 올리는 중입니다")
            if not self.plan:
                raise ValueError("올릴 것이 없습니다. 먼저 파일로 저장하세요")
            plan, self.pushing = self.plan, True
        try:
            res = push_plan(plan)
        finally:
            with self.lock:
                self.pushing = False
        with self.lock:
            if res["ok"] or res.get("moved"):
                self.plan = None   # 저장소가 바뀌었으면 같은 계획을 다시 돌리지 않는다
        res["opened"] = False
        if res["ok"] and res.get("pr_url") and self.open_browser:
            try:
                res["opened"] = bool(webbrowser.open(res["pr_url"]))
            except Exception:
                pass
        return res

    def _load(self):
        with open(self.spec_path, encoding="utf-8") as f:
            spec = json.load(f)
        with open(self.draft_path, encoding="utf-8") as f:
            draft = json.load(f)
        return spec, draft

    def state(self):
        with self.lock:   # 저장(os.replace)과 읽기가 겹치면 Windows에서 교체가 실패한다 (검토 B3)
            spec, draft = self._load()
        return {"spec": self.spec_path, "draft": self.draft_path, **build_state(spec, draft)}

    def preview(self, choices):
        with self.lock:
            spec, draft = self._load()
        return preview(spec, draft, choices)

    def save(self, choices):
        with self.lock:
            if self.pushing:
                raise ValueError("GitHub에 올리는 중입니다. 끝난 뒤에 저장하세요")
            spec, draft = self._load()
            issues = drift(spec, draft)
            if issues:
                raise ValueError("observe 뒤에 원본이 바뀌었다 (" + ", ".join(issues[:5]) + "). observe를 다시 돌린다")
            new, missing, changed = apply_choices(spec, draft, choices)
            if missing:
                return {"saved": False, "missing": missing}
            if not changed:
                return {"saved": False, "missing": [], "reason": "화면에서 정할 단계가 없다"}
            target, note = None, None
            if self.target_path:
                try:
                    target = Target.load(self.target_path)
                except (OSError, ValueError) as exc:
                    note = f"대상 파일을 읽지 못해 Gateway 관련 검사는 하지 않았다 ({exc.__class__.__name__})"
            res = save_spec(self.spec_path, new, target, expected=spec)
            self.plan = None   # 앞 저장의 계획은 버린다. 이번 저장에 문제가 없을 때만 새로 만든다
            locked = sum(1 for _, _, st, dst in _pairs(new, draft) if step_state(st, dst)[0] == "locked")
            records = sum(1 for c in changed for s in new["scenarios"] if s["id"] == c["id"]
                          and s["steps"][c["n"] - 1].get("expect", "x") is None)
            ids = list(dict.fromkeys(c["id"] for c in changed))
            git = None
            if not res["errors"]:
                try:
                    git = git_plan(self.spec_path, ids, dirty_before=res["dirty_before"])
                    self.plan = {**git, "sha": res["sha"]} if git.get("ok") and not locked else None
                except Exception:   # 저장은 끝났다. 올리기 안내만 못 만든 것 (검토 B1)
                    git = {"ok": False, "reason": "저장은 끝났습니다. GitHub에 올릴 명령은 만들지 못했으니 직접 올리세요"}
            return {"saved": True, "path": self.spec_path, "changed": len(changed), "locked": locked, "records": records,
                    "note": note, "git": git, **res}


PAGE_CSP = ("default-src 'none'; script-src 'nonce-{n}'; style-src 'nonce-{n}'; connect-src 'self'; "
            "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "gateprobe-ui"
    timeout = 30   # 본문을 다 보내지 않는 요청이 스레드를 붙잡지 않게

    def log_message(self, *args):   # 요청 기록을 찍지 않는다 (주소와 헤더가 콘솔에 남지 않게)
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", csp=None):
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        """Host와 Origin이 이 서버(127.0.0.1 또는 localhost와 실제 포트)일 때만 (DNS rebinding, 다른 사이트 요청 막기)."""
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if (self.headers.get("Host") or "").lower() not in hosts:
            return False
        origin = self.headers.get("Origin")
        return not origin or origin.lower() in {f"http://{h}" for h in hosts}

    def _token_ok(self):
        given = (self.headers.get("X-Gateprobe-Token") or "").encode()
        return secrets.compare_digest(given, self.server.app.token.encode())

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {"error": "이 주소로는 열 수 없다"})
        path = urlsplit(self.path).path
        app = self.server.app
        if path == "/":
            from gateprobe.ui_page import page
            return self._send(200, page(app.nonce), "text/html; charset=utf-8", PAGE_CSP.format(n=app.nonce))
        if path == "/api/state":
            if not self._token_ok():
                return self._send(403, {"error": "토큰이 맞지 않는다. 터미널에 나온 주소로 다시 연다"})
            try:
                return self._send(200, app.state())
            except Exception as exc:   # 형식이 예상과 다른 파일도 연결을 끊지 않고 이유를 보낸다
                return self._send(500, {"error": f"파일을 읽지 못했다: {exc.__class__.__name__}: {exc}"[:300]})
        return self._send(404, {"error": "없는 주소"})

    def do_POST(self):
        if not self._allowed():
            return self._send(403, {"error": "이 주소로는 보낼 수 없다"})
        if not self._token_ok():
            return self._send(403, {"error": "토큰이 맞지 않는다. 터미널에 나온 주소로 다시 연다"})
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._send(415, {"error": "JSON만 받는다"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self._send(413, {"error": "요청이 너무 크다"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            choices = body.get("choices") or {}
            if not isinstance(choices, dict):
                raise ValueError("choices 형식 오류")
            path = urlsplit(self.path).path
            if path == "/api/preview":
                return self._send(200, self.server.app.preview(choices))
            if path == "/api/save":
                return self._send(200, self.server.app.save(choices))
            if path == "/api/push":
                return self._send(200, self.server.app.push())
            return self._send(404, {"error": "없는 주소"})
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            return self._send(400, {"error": str(exc)[:300]})
        except OSError as exc:
            return self._send(500, {"error": f"파일을 읽거나 쓰지 못했다: {exc}"[:300]})
        except Exception as exc:
            return self._send(500, {"error": f"처리하지 못했다: {exc.__class__.__name__}: {exc}"[:300]})


class Server(ThreadingHTTPServer):
    allow_reuse_address = False   # Windows에서 같은 포트를 다른 프로세스가 가로채지 못하게
    daemon_threads = True


def make_server(app, port=0):
    srv = Server(("127.0.0.1", port), Handler)
    srv.app = app
    return srv


def serve(spec_path, draft_path, target_path=None, port=0, open_browser=True, log=print):
    app = App(spec_path, draft_path, target_path)
    app.open_browser = open_browser   # --no-browser면 올린 뒤 PR 페이지도 열지 않는다 (화면에 주소가 나옴)
    srv = make_server(app, port)
    url = f"http://127.0.0.1:{srv.server_address[1]}/#t={app.token}"
    log("정상 확인 화면을 열었다. 이 컴퓨터(127.0.0.1)에서만 열린다")
    log(f"  원본: {spec_path}")
    log(f"  초안: {draft_path}")
    log(f"브라우저가 열리지 않으면 이 주소를 붙여 넣는다: {url}")
    log("다 쓰면 이 창에서 Ctrl+C로 끝낸다")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:   # 브라우저가 없는 환경이면 위 주소로 연다
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("화면을 닫았다")
    finally:
        srv.server_close()
    return 0
