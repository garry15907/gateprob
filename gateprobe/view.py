"""보고서 화면(HTML, 마크다운)이 같이 쓰는 정리 단계. 기록 + 시나리오 파일 -> 분류별 시나리오 목록.

시나리오 파일에 아래 값이 있으면 쓴다 (없으면 id와 설명 첫 문장으로 대신함)
  시나리오마다  "제목" (짧게), "요약" (한 줄), "분류" (묶음 이름)
  파일 맨 위    "분류": {"묶음 이름": "이 묶음이 확인하는 것 한 줄"}   적은 순서대로 보여 준다

시나리오 결과 kind: blocked(막힘) allowed(허용) error(도구 오류) record(기록만) unknown(판정 불가)
                   incomplete(사전 준비 실패로 점검 안 됨) bad(불일치)
한 시나리오 안에서는 bad > unknown > incomplete 순으로 보인다(앞선 판정 불가가 뒤의 회귀를 가리지 않게).
결과 글자는 기대값이 있는 마지막 호출의 관찰로 정한다.
종합 판정은 runner.exit_code와 같은 규칙: 회귀가 있으면 fail, 판정 불가·사전 준비 실패·기대값 있는 호출 0개면 incomplete.
"""
from __future__ import annotations

import re

from gateprobe.report import _cases

LABEL = {"ALLOW": "허용", "IAM_DENY": "IAM 거부", "POLICY_DENY": "정책 거부", "TOOL_ERROR": "도구 오류", "UNKNOWN": "판정 불가"}
SHORT = {"ALLOW": "허용", "IAM_DENY": "차단", "POLICY_DENY": "차단", "TOOL_ERROR": "도구 오류", "UNKNOWN": "판정 불가"}
KIND = {"차단": "blocked", "허용": "allowed", "도구 오류": "error"}


def first_sentence(desc, limit=60):
    t = re.sub(r"^S\d[^.]*?\.\s+", "", (desc or "").strip())
    t = re.split(r"(?<=[^0-9])\.\s", t, maxsplit=1)[0].rstrip(".")
    t = re.sub(r"\s*\([^()]*\)", "", t)
    return t if len(t) <= limit else t[:limit - 2].rstrip() + "…"


def expected_text(exp, short=True):
    """'POLICY_DENY (규칙)|UNKNOWN [오류 정규식]' -> '차단' (short) 또는 '정책 거부 또는 요청 오류'."""
    t = re.sub(r"\s*\[[^\]]*\]", "", exp or "")
    parts = []
    for x in t.split("|"):
        x = re.sub(r"\s*\(.*\)$", "", x.strip())
        x = ("차단" if x == "UNKNOWN" else SHORT.get(x, x)) if short else ("요청 오류" if x == "UNKNOWN" else LABEL.get(x, x))
        if x not in parts:
            parts.append(x)
    return " 또는 ".join(parts) or "-"


def expected_codes(exp):
    """기대값 문자열 -> 결과 코드 집합. 'POLICY_DENY (규칙)|UNKNOWN [오류 정규식]' -> {'POLICY_DENY', 'UNKNOWN'}"""
    t = re.sub(r"\s*\[[^\]]*\]", "", exp or "")
    return {re.sub(r"\s*\(.*\)$", "", x.strip()) for x in t.split("|") if x.strip()}


DENY = {"IAM_DENY", "POLICY_DENY", "UNKNOWN"}   # 기대값의 UNKNOWN은 '요청 자체가 거부됨'(오류 정규식으로 확인)


def impact(r):
    """기대와 다른 호출 하나의 영향. 기대와 결과의 방향만으로 정한다(어느 업무인지는 분류 칸이 말한다).
    채점은 spec.matches가 이미 했다: 기대가 'IAM_DENY 또는 POLICY_DENY'였다면 어느 쪽으로 막혀도 일치다."""
    exp, obs = expected_codes(r.get("expected")), r["observed"]
    if obs == "UNKNOWN":
        return "응답으로 허용·거부를 가릴 수 없음"
    if obs == "ALLOW" and exp and exp <= DENY:
        return "차단돼야 할 호출이 허용됨"
    if obs in ("IAM_DENY", "POLICY_DENY") and "ALLOW" in exp:
        return "허용돼야 할 호출이 차단됨"
    if obs in ("IAM_DENY", "POLICY_DENY") and exp & {"IAM_DENY", "POLICY_DENY"}:
        return "차단 계층 변경"
    if obs == "TOOL_ERROR" and "ALLOW" in exp:
        return "허용돼야 할 호출이 도구 오류로 끝남"
    return "정상과 다른 결과"


MEANING = {"ALLOW": "도구가 실행되어 성공", "IAM_DENY": "백엔드 권한(IAM)이 거부", "POLICY_DENY": "Gateway 정책이 거부",
           "TOOL_ERROR": "도구가 오류를 돌려줌", "UNKNOWN": "허용·거부를 가릴 수 없는 응답"}


def response_text(r):
    """응답 코드만 보여 주면 읽는 사람이 뜻을 모른다. 뜻을 앞에 쓰고 원문은 괄호에."""
    raw = error_text(r)
    head = MEANING.get(r.get("observed"), "")
    return (f"{head} ({raw})" if head and raw else head or raw)[:240]


def error_text(r):
    status = r.get("http_status") if r.get("http_status") != 200 else None   # 200은 정상 응답이라 뜻이 없다
    t = " ".join(str(x) for x in (status, r.get("rpc_code"), r.get("rpc_message"), r.get("detail"), r.get("tool_text"))
                 if x not in (None, ""))
    return re.sub(r"(?<!\d)\d{12}(?!\d)", "<ACCOUNT>", t)   # IAM 거부 문구의 ARN에 계정 ID가 들어갈 수 있다


def flow(rows, tool_labels):
    """호출 순서. 같은 세션·도구·결과가 이어지면 묶는다 (공지 정책 거부 ×6)."""
    multi = len({r.get("session") for r in rows}) > 1
    out = []
    for r in rows:
        key = (r.get("session"), r["tool"], r["observed"], r["match"])
        if out and out[-1]["key"] == key:
            out[-1]["n"] += 1
            continue
        m, obs = r["match"], r["observed"]
        kind = "bad" if m is False else ("blocked" if obs in ("IAM_DENY", "POLICY_DENY") or (obs == "UNKNOWN" and m) else
                                         ("record" if m is None else "allowed"))
        out.append({"key": key, "n": 1, "kind": kind, "session": r.get("session") if multi else None,
                    "tool": tool_labels.get(r["tool"], r["tool"]),
                    "result": "요청 오류" if obs == "UNKNOWN" and m else LABEL.get(obs, obs)})
    return out


def result(rows):
    fixture = [r for r in rows if r["step"] == 0]
    regress = [r for r in rows if r["match"] is False and r["observed"] != "UNKNOWN"]
    unknown = [r for r in rows if r["match"] is False and r["observed"] == "UNKNOWN"]
    if fixture and not regress and not unknown:
        return {"kind": "incomplete", "word": "점검 안 됨", "note": "사전 준비 실패", "expected": "-", "got": "점검 안 됨",
                "impact": "사전 준비 실패로 점검하지 못함"}
    bad = regress or unknown
    if bad:
        r = bad[0]
        kind = "unknown" if r["observed"] == "UNKNOWN" else "bad"
        got = "판정 불가" if r["observed"] == "UNKNOWN" else SHORT.get(r["observed"], r["observed"])
        return {"kind": kind, "word": "확인 필요" if kind == "unknown" else "불일치",
                "note": f"{r['step']}단계 정상 {expected_text(r['expected'])}, 결과 {got}" if r["step"] else "사전 준비 실패",
                "impact": impact(r),
                "expected": expected_text(r["expected"]) if r["expected"] else "-",
                "got": "판정 불가" if r["observed"] == "UNKNOWN" else SHORT.get(r["observed"], r["observed"])}
    checked = [r for r in rows if r["match"] is not None]
    if not checked:
        return {"kind": "record", "word": "기록만", "note": "", "expected": "-", "got": "-"}
    obs = checked[-1]["observed"]
    word = "차단" if obs == "UNKNOWN" else SHORT.get(obs, obs)
    return {"kind": KIND.get(word, "allowed"), "word": word, "note": "",
            "expected": expected_text(checked[-1]["expected"]), "got": word}


def build(record, labels=None, scenarios=None, tool_labels=None, groups=None):
    """scenarios: {id: 설명 문자열} 또는 {id: 시나리오 dict}. groups: {분류: 한 줄 설명}"""
    labels, tools, groups = labels or {}, tool_labels or {}, groups or {}
    meta = {k: (v if isinstance(v, dict) else {"설명": v}) for k, v in (scenarios or {}).items()}
    s = record["summary"]
    gws = sorted(record["configs"], key=lambda g: list(labels).index(g) if g in labels else len(labels))
    name = lambda g: labels.get(g, g)
    by = {}
    for gw, sid, rows in _cases(record):
        by.setdefault(sid, {})[gw] = rows

    scen = []
    for sid, cells in by.items():
        m = meta.get(sid, {})
        res = [dict(result(cells[g]), config=name(g)) for g in gws if cells.get(g)]
        scen.append({"id": sid, "title": m.get("제목") or sid,
                     "summary": m.get("요약") or first_sentence(m.get("설명")),
                     "description": m.get("설명") or "", "group": m.get("분류") or "시나리오",
                     "results": res,
                     "flows": [{"config": name(g), "steps": flow(cells[g], tools)} for g in gws if cells.get(g)],
                     "bad": any(r["kind"] == "bad" for r in res),
                     "unknown": any(r["kind"] in ("unknown", "incomplete") for r in res),
                     "record": all(r["kind"] == "record" for r in res)})

    order = list(groups) + [x["group"] for x in scen if x["group"] not in groups]
    out_groups = []
    for g in dict.fromkeys(order):
        rows = [x for x in scen if x["group"] == g]
        if rows:
            chk = [x for x in rows if not x["record"]]
            out_groups.append({"name": g, "desc": groups.get(g, ""), "rows": rows, "checked": len(chk),
                               "ok": sum(not (x["bad"] or x["unknown"]) for x in chk)})

    issues = []
    for sc in scen:
        for g in gws:
            for r in by[sc["id"]].get(g, []):
                if r["step"] == 0:
                    issues.append({"title": sc["title"], "config": name(g), "step": 0, "tool": "사전 준비",
                                   "expected": "-", "got": "점검 안 됨", "impact": "사전 준비 실패로 점검하지 못함",
                                   # 예외 문구에 ARN·계정 ID가 들어갈 수 있다 (외부 검토 11-23)
                                   "response": re.sub(r"(?<!\d)\d{12}(?!\d)", "<ACCOUNT>", str(r.get("error") or ""))[:240]})
                elif r["match"] is False:
                    issues.append({"title": sc["title"], "config": name(g), "step": r["step"],
                                   "tool": tools.get(r["tool"], r["tool"]), "expected": expected_text(r["expected"]),
                                   "got": "판정 불가" if r["observed"] == "UNKNOWN" else SHORT.get(r["observed"], r["observed"]),
                                   "impact": impact(r),
                                   "response": response_text(r)})

    n_bad = sum(x["bad"] for x in scen)
    n_unk = sum(x["unknown"] and not x["bad"] for x in scen)
    n_rec = sum(x["record"] for x in scen)
    n_chk = len(scen) - n_rec
    # 터미널, HTML, CI 요약이 같은 낱말을 쓴다: 종합 판정 적합/부적합/점검 미완료, 항목 판정 일치/불일치/확인 필요/기록만
    if n_bad:
        verdict, head = "fail", f"부적합 (불일치 {n_bad}건)"
    elif n_unk or s.get("fixture_errors") or not s.get("checked"):
        verdict = "incomplete"
        head = "점검 미완료" + (f" (확인 필요 {n_unk}건)" if n_unk else " (정상을 정해 둔 호출 없음)")
    else:
        verdict, head = "pass", "적합"
    from gateprobe import __version__
    line = (f"판정 대상 {n_chk}개 항목 중 일치 {n_chk - n_bad - n_unk}개, 불일치 {n_bad}개, 확인 필요 {n_unk}개"
            + (f", 기록만 {n_rec}개" if n_rec else ""))
    return {"verdict": verdict, "head": head, "version": __version__, "line": line,
            "n_scenarios": len(scen), "n_checked": n_chk, "n_bad": n_bad, "n_unknown": n_unk, "n_record": n_rec,
            "configs": [name(g) for g in gws], "calls": s["calls"], "spec": record.get("spec") or "",
            "when": (record.get("created_utc") or "")[:16].replace("T", " "), "groups": out_groups, "issues": issues}
