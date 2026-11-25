"""정적 HTML 보고서 한 장 (점검 결과서 형식). 서버 없이 브라우저로 연다. 인쇄하면 접힌 호출 흐름도 펼쳐서 찍힌다.

접근성(검토 11-23): 표 머리글 scope, 표 제목(caption), 판정은 색과 함께 글자로, 회색 대비 7:1 이상, 최소 12px,
좁은 화면에서는 표만 가로로 스크롤.

국내 보안 점검 결과표처럼 종합 판정 -> 분류별 결과 -> 항목별 결과(양호/취약) 순서로 쓴다.
내용 정리는 view.build가 하고 여기서는 모양만 정한다.
"""
from __future__ import annotations

from html import escape as e

from gateprobe import view

# 판정은 '기대 동작과의 일치 여부'다. 좋고 나쁨(양호/취약)이 아니다: 정상 호출이 막혀도, 대조군에서 예측한 유출이
# 그대로 나와도 기대와 비교한 결과일 뿐이다. 불일치의 업무 영향은 따로 적는다(view.impact).
JUDGE = {"blocked": "일치", "allowed": "일치", "error": "일치", "bad": "불일치", "unknown": "확인 필요",
         "incomplete": "확인 필요", "record": "기록만"}
JCLS = {"불일치": "bad", "확인 필요": "warn", "기록만": "mut"}
RANK = ["기록만", "일치", "확인 필요", "불일치"]   # 구성 중 하나라도 판정했으면 기록보다 그 판정을 보인다

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#e9e9e9;font:13px/1.55 "Malgun Gothic","Apple SD Gothic Neo",sans-serif;color:#111}
.paper{max-width:860px;margin:24px auto;background:#fff;padding:48px 52px;border:1px solid #cfcfcf}
h1{font:700 22px "Batang","바탕","Noto Serif KR",serif;text-align:center;letter-spacing:6px;margin:0 0 26px}
h2{font-size:14px;margin:0 0 6px}
table{border-collapse:collapse;width:100%;margin:0 0 22px}
th,td{border:1px solid #777;padding:6px 8px;vertical-align:middle}
th{background:#ececec;font-weight:700}
.info th{width:90px}
.c{text-align:center}.cat{text-align:center;font-weight:700;background:#fafafa;width:84px;word-break:keep-all}
.s{color:#555;font-size:12px}
.j{font-weight:700;width:96px;text-align:center}.imp{display:block;font-size:12px;font-weight:400;word-break:keep-all}.bad{color:#c00000}.warn{color:#9a6700}.mut{color:#595959;font-weight:400}
.cfg{display:block;font-size:12px;color:#595959}
.verdict{border:2px solid #111;padding:10px 14px;margin:0 0 22px;font-size:14px}
.verdict b{font-size:16px}.verdict.bad{border-color:#c00000}.verdict.bad b{color:#c00000}
.verdict.warn{border-color:#9a6700}.verdict.warn b{color:#9a6700}
.issue td{font-size:12px}.issue .resp{color:#555;word-break:break-all}
details{font-size:12px;color:#444;margin-top:2px}details summary{cursor:pointer;width:max-content}
.tw{overflow-x:auto;margin:0 0 22px}.tw table{margin:0}td{overflow-wrap:anywhere}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}.pflow{display:none}
.flow .blocked{font-weight:700;color:#111}.flow .bad{color:#c00000;font-weight:700}.flow .ses{border:1px solid #bbb;padding:0 3px;margin-right:2px}
.foot{font-size:12px;color:#444;border-top:1px solid #999;padding-top:8px}
@media (max-width:700px){.paper{padding:20px 12px;margin:0;border:0}th,td{padding:4px 5px}.cat{width:auto}}
@media print{body{background:#fff}.paper{margin:0;border:0;padding:0}details{display:none}.pflow{display:block;font-size:11px;color:#333}tr{break-inside:avoid}.tw{overflow:visible}}
"""


def flow_html(steps):
    parts = []
    for st in steps:
        ses = f"<span class='ses'>{e(str(st['session']))}</span>" if st["session"] is not None else ""
        n = f" ×{st['n']}" if st["n"] > 1 else ""
        mark = {"bad": " (불일치)", "unknown": " (확인 필요)"}.get(st["kind"], "")   # 색만으로 알리지 않는다
        parts.append(f"<span class='{st['kind']}'>{ses}{e(st['tool'])} {e(st['result'])}{n}{mark}</span>")
    return " → ".join(parts)



def render(record, labels=None, scenarios=None, tool_labels=None, groups=None, source=None):
    """source: 점검 기록 파일 이름. 결과서 두 개를 나란히 볼 때 어느 기록인지 구분하려고 제목과 머리에 넣는다."""
    v = view.build(record, labels, scenarios, tool_labels, groups)
    multi = len(v["configs"]) > 1

    # 1. 분류별 결과
    summ = []
    for g in v["groups"]:
        n_bad = sum(sc["bad"] for sc in g["rows"])
        n_unk = sum(sc["unknown"] and not sc["bad"] for sc in g["rows"])
        summ.append(f"<tr><td class='c'>{e(g['name'])}</td><td>{e(g['desc'])}</td><td class='c'>{g['checked']}</td>"
                    f"<td class='c'>{g['ok']}</td><td class='c{' bad' if n_bad else ''}'>{n_bad}</td>"
                    f"<td class='c{' warn' if n_unk else ''}'>{n_unk}</td></tr>")

    # 2. 항목별 결과
    rows = []
    for gi, g in enumerate(v["groups"], 1):
        for k, sc in enumerate(g["rows"], 1):
            res = sc["results"]
            if multi:   # 구성마다 기대가 다를 수 있으므로 결과 칸과 같은 줄 배치로
                expect = "".join(f"<span class='cfg'>{e(r['config'])}</span><div>{e(r['expected'])}</div>" for r in res)
            else:
                expect = e(res[0]["expected"])
            got = "".join((f"<span class='cfg'>{e(r['config'])}</span>" if multi else "")
                          + f"<div class='{JCLS.get(JUDGE[r['kind']], '')}'>{e(r['got'])}</div>" for r in res)
            judge = max((JUDGE[r["kind"]] for r in res), key=RANK.index)
            imps = list(dict.fromkeys(r["impact"] for r in res if r.get("impact")))
            imp = "".join(f"<span class='imp'>{e(x)}</span>" for x in imps)
            cat = f"<td rowspan='{len(g['rows'])}' class='cat'>{e(g['name'])}</td>" if k == 1 else ""
            flows = "".join(f"<div class='flow'>{(e(f['config']) + ': ') if multi else ''}{flow_html(f['steps'])}</div>" for f in sc["flows"])
            summary = f"<div class='s'>{e(sc['summary'])}</div>" if sc["summary"] else ""
            rows.append(f"<tr><td class='c'>{gi}-{k}</td>{cat}<td><b>{e(sc['title'])}</b>{summary}"
                        f"<details><summary aria-label='호출 보기: {e(sc['title'])}'>호출 보기</summary>{flows}</details>"
                        f"<div class='pflow'>{flows}</div></td>"
                        f"<td class='c'>{expect}</td><td class='c'>{got}</td>"
                        f"<td class='j {JCLS.get(judge, '')}'>{judge}{imp}</td></tr>")

    # 3. 불일치·확인 필요 호출의 상세
    issues = ""
    if v["issues"]:
        trs = "".join(f"<tr><td>{e(i['title'])}{(' · ' + e(i['config'])) if multi else ''}</td><td class='c'>{i['step']}</td>"
                      f"<td class='c'>{e(i['tool'])}</td><td class='c'>{e(i['expected'])}</td><td class='c bad'>{e(i['got'])}</td>"
                      f"<td>{e(i.get('impact', ''))}</td>"
                      f"<td class='resp'>{e(i['response'] or '(응답 내용 없음)')}</td></tr>" for i in v["issues"])
        issues = (f"<h2>3. 불일치 호출 상세</h2><div class='tw'><table class='issue'><caption class='sr'>불일치·확인 필요 호출 상세</caption>"
                  f"<tr><th scope='col'>점검 항목</th><th scope='col'>단계</th><th scope='col'>도구</th><th scope='col'>정상</th>"
                  f"<th scope='col'>결과</th><th scope='col'>영향</th><th scope='col'>Gateway 응답</th></tr>{trs}</table></div>")

    if v["verdict"] == "pass":
        verdict, vcls = "적합", ""
    elif v["verdict"] == "fail":
        verdict, vcls = "부적합", " bad"
    else:   # 판정 불가, 사전 준비 실패, 기대값을 확인한 호출 0개: 통과로 보이면 안 된다
        verdict, vcls = "점검 미완료", " warn"
    title = "정책 점검 결과서" + (f" · {source}" if source else "")
    src_row = f"<tr><th scope='row'>점검 기록</th><td colspan='3'>{e(source)}</td></tr>" if source else ""
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><div class="paper">
<h1>정책 점검 결과서</h1>
<div class="tw"><table class="info"><caption class="sr">점검 정보</caption><tr><th scope="row">점검 대상</th><td>{e(', '.join(v['configs']))}</td><th scope="row">점검 일시</th><td>{e(v['when'])} UTC</td></tr>
<tr><th scope="row">점검 도구</th><td>gateprobe (고정 호출 {v['calls']}건)</td><th scope="row">시나리오</th><td>{v['n_scenarios']}개</td></tr>{src_row}</table></div>
<div class="verdict{vcls}">종합 판정: <b>{verdict}</b> &nbsp;—&nbsp; {e(v['line'])}</div>
<h2>1. 분류별 결과</h2>
<div class="tw"><table><caption class="sr">분류별 결과</caption><tr><th scope="col">분류</th><th scope="col">점검 내용</th><th scope="col">항목</th><th scope="col">일치</th><th scope="col">불일치</th><th scope="col">확인 필요</th></tr>{''.join(summ)}</table></div>
<h2>2. 항목별 결과</h2>
<div class="tw"><table><caption class="sr">항목별 결과: 정상(미리 정한 올바른 동작), 결과, 판정</caption><tr><th scope="col">번호</th><th scope="col">분류</th><th scope="col">점검 항목</th><th scope="col">정상</th><th scope="col">결과</th><th scope="col">판정</th></tr>{''.join(rows)}</table></div>
{issues}
<div class="foot">정상: 시나리오를 쓴 사람이 미리 정해 둔 올바른 동작(차단 또는 허용). 판정: 결과가 정상과 같은지.
일치: 정상대로 차단되거나 허용됨(정상이 'IAM 또는 정책 차단'이면 어느 쪽에서 차단돼도 일치)
· 불일치: 정상과 다름, 아래 작은 글씨가 업무 영향 · 확인 필요: 응답으로 허용·거부를 가릴 수 없거나 사전 준비 실패 · 기록만: 정상을 정해 두지 않고 결과만 남김<br>
분류는 시나리오를 쓴 사람이 정한 묶음이다(예: "설계상 허용"은 정상이 허용인 항목). 판정은 결과가 정상과 같은지를 따로 본다.<br>
gateprobe {e(v.get('version', ''))} · 
시나리오 묶음: {e(v['spec'])}<br>
모델 없이 정해진 도구 호출을 Gateway에 보내 확인한 결과이며, 모델이 실제로 이런 호출을 할지는 다루지 않는다.</div>
</div></body></html>
"""


def summarize_legacy(record):
    """summary가 없는 예전 trace_check 기록에 요약을 붙인다."""
    if "summary" in record:
        return record
    rows = [r for v in record["configs"].values() for r in v]
    record["summary"] = {"calls": len(rows), "checked": sum(r["match"] is not None for r in rows),
                         "passed": sum(r["match"] is True for r in rows),
                         "regressions": sum(r["match"] is False and r["observed"] != "UNKNOWN" for r in rows),
                         "unknown": sum(r["match"] is False and r["observed"] == "UNKNOWN" for r in rows), "fixture_errors": 0}
    return record
