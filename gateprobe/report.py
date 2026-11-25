"""기록을 JUnit XML(CI 화면용)과 마크다운 요약(GitHub 작업 요약 등)으로 바꾼다."""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr


def _cases(record):
    for gw, rows in record["configs"].items():
        order, by = [], {}
        for r in rows:
            if r["scenario"] not in by:
                order.append(r["scenario"])
                by[r["scenario"]] = []
            by[r["scenario"]].append(r)
        for sid in order:
            yield gw, sid, by[sid]


def _line(r):
    return f"{r['step']} {r['tool']}: 정상 {r['expected']} 결과 {r['observed']}" + (f" ({r.get('error')})" if r.get("error") else "")


def junit(record):
    suites = {}
    for gw, sid, rows in _cases(record):
        bad = [r for r in rows if r["match"] is False and r["observed"] != "UNKNOWN"]
        unk = [r for r in rows if (r["match"] is False and r["observed"] == "UNKNOWN") or r["step"] == 0]
        body = "\n".join(_line(r) for r in rows)
        if bad:
            inner = f'<failure message={quoteattr("불일치: " + "; ".join(_line(r) for r in bad))}>{escape(body)}</failure>'
        elif unk:
            inner = f'<error message={quoteattr("판정 불가: " + "; ".join(_line(r) for r in unk))}>{escape(body)}</error>'
        elif all(r["match"] is None for r in rows):
            inner = '<skipped message="기대값 없음 (기록만)"/>'
        else:
            inner = f"<system-out>{escape(body)}</system-out>"
        suites.setdefault(gw, []).append((sid, inner, bool(bad), bool(unk and not bad)))
    out = ['<?xml version="1.0" encoding="UTF-8"?>', f'<testsuites name={quoteattr(record.get("spec") or "gateprobe")}>']
    for gw, cases in suites.items():
        out.append(f'  <testsuite name={quoteattr(gw)} tests="{len(cases)}" failures="{sum(c[2] for c in cases)}" '
                   f'errors="{sum(c[3] for c in cases)}">')
        for sid, inner, _, _ in cases:
            out.append(f'    <testcase classname={quoteattr(gw)} name={quoteattr(sid)}>{inner}</testcase>')
        out.append("  </testsuite>")
    out.append("</testsuites>")
    return "\n".join(out) + "\n"


def markdown(record, labels=None, scenarios=None, tool_labels=None, groups=None):
    """GitHub 작업 요약용. HTML 보고서와 같은 제목, 분류, 결과(차단/허용)를 쓴다."""
    from gateprobe import view   # view가 이 모듈의 _cases를 쓰므로 여기서 읽는다

    v = view.build(record, labels, scenarios, tool_labels, groups)
    multi = len(v["configs"]) > 1
    # 첫 줄에 결론. HTML 결과서의 종합 판정 줄과 같은 낱말 (검토 11-23)
    lines = [f"### 종합 판정: {v['head']}", "", f"{v['line']}  ",
             f"{v['spec']} · {', '.join(v['configs'])} · 호출 {v['calls']}번 · gateprobe {v['version']}", ""]
    if v["issues"]:
        lines += ["**불일치·확인 필요 호출**", ""]
        lines += [f"- {i['title']}" + (f" ({i['config']})" if multi else "") + f" · {i['step']}단계 {i['tool']}: "
                  f"정상 {i['expected']}, 결과 {i['got']} → {i.get('impact', '')}" for i in v["issues"]]
        lines.append("")
    head = "| 분류 (일치/판정 대상) | 점검 항목 | " + (" | ".join(v["configs"]) if multi else "결과") + " |"
    lines += [head, "| --- | --- |" + " --- |" * (len(v["configs"]) if multi else 1)]
    for g in v["groups"]:
        for k, sc in enumerate(g["rows"]):
            cat = f"{g['name']} ({g['ok']}/{g['checked']})" if k == 0 and g["checked"] else (g["name"] if k == 0 else "")
            title = sc["title"] + (f"<br><sub>{sc['summary']}</sub>" if sc["summary"] else "")
            cells = []
            for r in sc["results"]:
                w = f"**{r['word']}**" if r["kind"] in ("bad", "unknown", "incomplete") else r["word"]
                note = "; ".join(x for x in (r.get("note"), r.get("impact")) if x)
                cells.append(w + (f" ({note})" if note else ""))
            lines.append(f"| {cat} | {title.replace('|', '/')} | " + " | ".join(cells) + " |")
    lines += ["", "<sub>정상: 시나리오를 쓴 사람이 미리 정한 올바른 동작(차단 또는 허용). 일치/불일치: 결과가 정상과 같은지. "
                  "확인 필요: 응답으로 허용·차단을 가릴 수 없음. 자세한 결과서(HTML)는 실행 산출물에 있다.</sub>"]
    return "\n".join(lines) + "\n"
