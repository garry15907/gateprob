"""정상 확인 화면의 HTML 한 장. 설치 파일에 빠지지 않게 파이썬 문자열로 둔다 (검토 B4).

외부 글꼴·라이브러리 없이 동작한다. 파일 내용은 textContent로만 넣는다 (XSS 방지).
스크립트와 스타일에는 실행마다 만든 nonce를 붙이고 서버가 CSP로 그 밖의 것을 막는다.
"""

PAGE = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>gateprobe 정상 확인</title>
<style nonce="__NONCE__">
*{box-sizing:border-box}
body{margin:0;background:#e9e9e9;font:15px/1.6 "Malgun Gothic","Apple SD Gothic Neo",sans-serif;color:#111}
.paper{max-width:860px;margin:24px auto;background:#fff;padding:36px 44px;border:1px solid #cfcfcf}
h1{font-size:22px;margin:0 0 6px}
h2{font-size:16px;margin:0 0 4px}
.files,.s,.grp,.sum,.lbl,.oh,.dec,.lock,.note{color:#595959}
.files{font-size:12px;margin:0 0 16px;overflow-wrap:anywhere}
.guide{border:1px solid #777;padding:10px 14px;margin:0 0 16px}
.guide p{margin:0 0 6px}
summary{cursor:pointer;width:max-content}
dl.terms{margin:6px 0 0;display:grid;grid-template-columns:max-content minmax(0,1fr);gap:2px 12px}
dl.terms dt{font-weight:700}dl.terms dd{margin:0}
#progress{font-weight:700;margin:0 0 12px}
.card{border-top:2px solid #111;padding:12px 0 4px;margin:0 0 18px}
.grp{font-size:12px;margin:0}.sum{margin:2px 0 8px}
.step{border-top:1px solid #bbb;padding:12px 0}
.sh{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.sn{font-weight:700}
code,pre{font-family:Consolas,"D2Coding",monospace}
.badge{font-size:12px;border:1px solid #777;padding:0 6px}
dl.args{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:0 10px;margin:6px 0;font-size:13px}
dl.args dt{color:#595959}dl.args dd{margin:0;overflow-wrap:anywhere}
.now{margin:6px 0}.lbl{font-size:12px}
fieldset{border:0;margin:8px 0 0;padding:0;min-width:0}
legend{font-weight:700;padding:0;margin:0 0 4px;font-size:13px}
.where legend{font-weight:400;color:#595959}
.opts{display:flex;flex-wrap:wrap;gap:8px}
.opt{display:grid;grid-template-columns:auto minmax(0,1fr);column-gap:6px;align-items:start;border:1px solid #777;padding:6px 10px;cursor:pointer;min-width:170px}
.opt input{margin:4px 0 0;grid-row:span 2}
.ol{font-weight:700}.oh{font-size:13px}
.opt:has(input:checked){border:2px solid #111;background:#f2f2f2;padding:5px 9px}
.opt:has(input:disabled){cursor:not-allowed;border-color:#bbb}
.opt:has(input:disabled) .ol{color:#595959}
.opt:has(input:focus-visible){outline:3px solid #1a5fb4;outline-offset:2px}
.note{margin:6px 0 0;font-size:13px}
.warn{color:#7a5200;font-weight:700}
.bad{color:#c00000;font-weight:700}
.ok{font-weight:700}
.bottom{border-top:2px solid #111;padding-top:12px;margin-top:8px}
button{font:inherit;padding:6px 14px;border:1px solid #111;background:#fff;color:#111;cursor:pointer}
button:disabled{color:#595959;border-color:#bbb;cursor:not-allowed}
button.link{border:0;padding:0;text-decoration:underline;background:none;color:#1a4f9c;text-align:left}
button:focus-visible,a:focus-visible,pre:focus-visible,summary:focus-visible{outline:3px solid #1a5fb4;outline-offset:2px}
pre.cmd{background:#f4f4f4;border:1px solid #bbb;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;margin:8px 0}
a{color:#1a4f9c;overflow-wrap:anywhere}
#status p,#git p{margin:4px 0}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
ol.howto{margin:0 0 6px;padding-left:20px}
@media (max-width:700px){.paper{margin:0;padding:16px 12px;border:0}.opt{min-width:0;flex:1 1 100%}}
</style></head>
<body><main class="paper">
<h1>정상 확인</h1>
<p class="files" id="files"></p>
<div class="guide">
<ol class="howto"><li>단계마다 그 호출이 통과해야 하는지(허용), 막혀야 하는지(차단)를 고릅니다. 이것을 <b>정상</b>이라 부릅니다</li>
<li>맨 아래 <b>파일로 저장</b>을 누릅니다</li>
<li>(선택) 저장 뒤 나오는 명령으로 GitHub에 올립니다</li></ol>
<p>정상은 업무 규칙을 아는 사람이 정하는 칸이라 미리 채워 두지 않았습니다. <b>지금 결과</b>는 지금 정책에 시험 호출을 한 번 보내 본 결과(observe 단계)일 뿐 정답이 아닙니다. 업무 규칙에 따라 고릅니다.</p>
<details><summary>말 풀이</summary><dl class="terms">
<dt>허용</dt><dd>호출이 통과해 도구가 실행됨</dd>
<dt>차단 (정책)</dt><dd>Gateway에 붙은 정책이 막음</dd>
<dt>차단 (권한)</dt><dd>도구 뒤의 AWS 권한(IAM)이 막음</dd>
<dt>기록만</dt><dd>결과만 적고 맞는지 검사하지 않음</dd>
<dt>도구 오류</dt><dd>도구는 실행됐지만 업무 오류를 돌려줌 (예: 잔액 부족)</dd>
<dt>판정 불가</dt><dd>연결 오류 등으로 결과를 나누지 못함</dd>
<dt>validate</dt><dd>파일 형식 검사</dd>
<dt>PR</dt><dd>바꾼 내용을 검토해 달라고 GitHub에 올리는 요청</dd>
<dt>CI</dt><dd>PR을 올리면 자동으로 도는 점검</dd>
</dl><p class="s">고를 수 있는 것은 허용, 차단, 기록만입니다. 도구 오류와 판정 불가는 지금 결과에만 나오고, 그런 단계는 파일에서 정합니다.</p></details>
</div>
<p id="progress" aria-live="polite"></p>
<div id="issues" role="alert"></div>
<div id="list"></div>
<section class="bottom" aria-labelledby="sv">
<h2 id="sv">저장</h2>
<p id="cmp" class="s"></p>
<button id="save" type="button">파일로 저장</button>
<div id="status" role="status"></div>
<div id="git"></div>
</section>
</main>
<script nonce="__NONCE__">
(function () {
"use strict";
var KEY = "gateprobe-ui-token";
var T = new URLSearchParams(location.hash.slice(1)).get("t") || "";
try { if (T) sessionStorage.setItem(KEY, T); else T = sessionStorage.getItem(KEY) || ""; } catch (e) {}
if (location.hash) history.replaceState(null, "", "/");   // 주소창에 토큰이 남지 않게 (화면 녹화 대비)
var $ = function (id) { return document.getElementById(id); };
var S = null, choices = {}, dirty = false, timer = null, lastSaved = 0, seq = 0;
var PICKS = [["ALLOW", "허용", "이 호출은 통과해야 한다"], ["DENY", "차단", "이 호출은 막혀야 한다"],
             ["RECORD", "기록만 (검사 안 함)", "결과만 적고 맞는지 보지 않는다"]];
var WHERES = [["POLICY_DENY", "정책", "Gateway 정책이 막는다"], ["IAM_DENY", "권한 (IAM)", "AWS 권한 설정이 막는다"],
              ["ANY", "어디서든", "어느 쪽이 막아도 정상"]];

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function api(path, body) {
  var opt = {headers: {"X-Gateprobe-Token": T}};
  if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  return fetch(path, opt).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (j) {
      if (!r.ok) throw new Error(j.error || ("응답 오류 " + r.status));
      return j;
    });
  });
}
function get(sid, n) { return (choices[sid] || {})[String(n)]; }
function set(sid, n, v) { (choices[sid] = choices[sid] || {})[String(n)] = v; }
function sid(sc, st) { return sc.id + "-" + st.n; }

function radio(name, value, label, hint, checked, disabled, describedby) {
  var lab = el("label", "opt"), inp = document.createElement("input"), h = el("span", "oh", hint);
  h.id = name + "-" + value + "-h";
  inp.type = "radio"; inp.name = name; inp.value = value; inp.checked = !!checked; inp.disabled = !!disabled;
  inp.setAttribute("aria-label", label);   // 화면 읽기 프로그램이 값(ALLOW)이 아니라 '허용'으로 읽게
  inp.setAttribute("aria-describedby", h.id + (describedby ? " " + describedby : ""));
  lab.append(inp, el("span", "ol", label), h);
  return lab;
}
function argsList(args) {
  var dl = el("dl", "args");
  Object.keys(args || {}).forEach(function (k) {
    var v = args[k];
    dl.append(el("dt", null, k), el("dd", null, typeof v === "string" ? v : JSON.stringify(v)));
  });
  return dl;
}
function renderStep(sc, st) {
  var box = el("div", "step"); box.id = "st-" + sid(sc, st);
  var head = el("div", "sh");
  head.append(el("span", "sn", st.n + "단계"), el("code", null, st.tool));
  if (st.wait) head.append(el("span", "badge", st.wait + "초 기다린 뒤"));
  box.append(head, argsList(st.args));
  if (st.kind === "decided") { box.append(el("p", "dec", "정해 둠: " + st.why)); return box; }
  var now = el("p", "now"); now.append(el("span", "lbl", "지금 결과: "), el("span", null, st.now || "없음"));
  box.append(now);
  if (st.kind === "locked") { box.append(el("p", "lock", "화면에서 정할 수 없음: " + st.why)); return box; }
  var c = get(sc.id, st.n) || {}, noteId = "note-" + sid(sc, st);
  var fs = el("fieldset", "pick"), row = el("div", "opts");
  var lg = el("legend"); lg.append(el("span", "sr", sc.title + " "), document.createTextNode(st.n + "단계: 이 호출은 어떻게 되어야 하나요?"));   // '2단계 정상'이 '문제없다'로 읽힘 (검토 E3)
  fs.append(lg);
  PICKS.forEach(function (p) { row.append(radio("p-" + sid(sc, st), p[0], p[1], p[2], c.pick === p[0], false, noteId)); });
  fs.append(row);
  var ws = el("fieldset", "where"), wrow = el("div", "opts");
  var wl = el("legend"); wl.append(el("span", "sr", sc.title + " " + st.n + "단계 "), document.createTextNode("어디서 막혀야 하나 (차단일 때. 처음 값은 정책)"));
  ws.append(wl);
  WHERES.forEach(function (w) {
    wrow.append(radio("w-" + sid(sc, st), w[0], w[1], w[2], c.pick === "DENY" && (c.where || "POLICY_DENY") === w[0], c.pick !== "DENY"));
  });
  ws.append(wrow);
  var note = el("p", "note"); note.id = noteId; note.setAttribute("aria-live", "polite");
  box.append(fs, ws, note);
  fs.addEventListener("change", function (e) {
    var cur = get(sc.id, st.n) || {};
    cur.pick = e.target.value;
    if (cur.pick === "DENY" && !cur.where) cur.where = "POLICY_DENY";   // 지금 결과와 상관없이 고정 (검토 A2, B7)
    set(sc.id, st.n, cur); dirty = true;
    ws.querySelectorAll("input").forEach(function (i) { i.disabled = cur.pick !== "DENY"; i.checked = cur.pick === "DENY" && i.value === cur.where; });
    refresh();
  });
  ws.addEventListener("change", function (e) {
    var cur = get(sc.id, st.n) || {}; cur.where = e.target.value; set(sc.id, st.n, cur); dirty = true; refresh();
  });
  return box;
}
function render() {
  var f = $("files"); f.textContent = "";
  f.append(el("span", null, "원본: " + S.spec), el("br"), el("span", null, "초안: " + S.draft));
  var iss = $("issues"); iss.textContent = "";
  if (S.issues.length) {
    iss.append(el("p", "bad", "observe 뒤에 원본이 바뀌어 이 초안으로는 저장할 수 없습니다. observe를 다시 돌린 뒤 여세요."));
    var ul = el("ul"); S.issues.forEach(function (x) { ul.append(el("li", null, x)); }); iss.append(ul);
    $("save").disabled = true;
  }
  var list = $("list"); list.textContent = "";
  S.scenarios.forEach(function (sc) {
    var sec = el("section", "card");
    sec.append(el("h2", null, sc.title));
    if (sc.group) sec.append(el("p", "grp", sc.group));
    if (sc.summary) sec.append(el("p", "sum", sc.summary));
    sc.steps.forEach(function (st) { sec.append(renderStep(sc, st)); });
    list.append(sec);
  });
  if (S.hidden) list.append(el("p", "s", "정상이 이미 정해진 시나리오 " + S.hidden + "개는 숨겼습니다."));
  refresh();
}
function pickSteps() {
  var out = [];
  (S ? S.scenarios : []).forEach(function (sc) { sc.steps.forEach(function (st) { if (st.kind === "pick") out.push([sc, st]); }); });
  return out;
}
function refresh() {
  var steps = pickSteps();
  var done = steps.filter(function (x) { return (get(x[0].id, x[1].n) || {}).pick; }).length;
  var locked = S ? S.counts.locked : 0;
  $("progress").textContent = (steps.length ? "고를 단계 " + steps.length + "개 중 " + done + "개 고름"
    : lastSaved ? "모든 단계를 정했고 저장했습니다 (정상을 정한 단계 " + lastSaved + "개)" : "화면에서 고를 단계가 없습니다") +
    (locked ? ". 파일에서 정해야 하는 단계 " + locked + "개" : "");
  clearTimeout(timer); timer = setTimeout(doPreview, 150);
}
function doPreview() {
  if (!pickSteps().length) { $("cmp").textContent = ""; return; }
  var my = ++seq;
  api("/api/preview", {choices: choices}).then(function (P) {
    if (my !== seq) return;   // 더 새 요청이 있으면 버린다
    pickSteps().forEach(function (x) {
      var n = $("note-" + sid(x[0], x[1])); if (!n) return;
      var k = P.rows[x[0].id + "/" + x[1].n];
      n.className = "note" + (k === "diff" ? " warn" : "");
      n.textContent = k === "diff" ? "참고: 지금 결과와 다릅니다. 정책이 틀렸거나 고른 정상이 틀렸을 수 있습니다."
        : k === "same" ? "참고: 지금 결과와 같습니다. 같아도 정답이라는 뜻은 아닙니다."
        : k === "record" ? "검사하지 않고 결과만 기록합니다."
        : k === "unknown" ? "지금 결과와 비교할 수 없습니다." : "";
    });
    $("cmp").textContent = "참고 (한 번 보내 본 결과 기준): 지금 결과와 다른 단계 " + P.diff + "개" +
      (P.unknown ? ", 비교 못 한 단계 " + P.unknown + "개" : "") + (P.record ? ", 기록만 " + P.record + "개" : "");
  }).catch(function () {});
}
function focusStep(id, n) {
  var box = $("st-" + id + "-" + n); if (!box) return;
  box.scrollIntoView({block: "center"});
  var i = box.querySelector("input"); if (i) i.focus();
}
function showGit(g) {
  var box = $("git"); box.textContent = "";
  if (!g) return;
  box.append(el("h2", null, "GitHub에 올리기 (선택)"));
  if (!g.ok) { box.append(el("p", null, g.reason)); return; }
  box.append(el("p", null, "터미널에서 아래 명령을 차례로 실행합니다. 새 브랜치를 만들어 " + g.file + " 하나만 커밋하고 올립니다. GitHub를 쓰지 않으면 건너뜁니다."));
  var text = g.commands.join("\n"), pre = el("pre", "cmd", text);
  pre.tabIndex = 0; pre.setAttribute("aria-label", "실행할 명령");
  var b = el("button", null, "명령 복사"), msg = el("span", "s");
  b.type = "button"; msg.setAttribute("role", "status");
  b.addEventListener("click", function () {
    var done = function () { msg.textContent = " 복사했습니다"; };
    var fallback = function () {
      var r = document.createRange(); r.selectNodeContents(pre);
      var s = getSelection(); s.removeAllRanges(); s.addRange(r);
      msg.textContent = " 선택했습니다. Ctrl+C로 복사하세요";
    };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
  });
  box.append(pre, b, msg);
  if (g.pr_url) {
    var p = el("p", null, "올리기가 끝나면 이 주소에서 PR을 만듭니다. PR을 열면 CI가 새 정상으로 점검합니다: ");
    var a = el("a", null, g.pr_url); a.href = g.pr_url; a.target = "_blank"; a.rel = "noopener noreferrer";
    p.append(a); box.append(p);
  }
  if (g.warnings.length) {
    box.append(el("p", null, "저장은 끝났습니다. 아래는 올릴 때 참고할 점입니다."));
    var ul = el("ul", "warn"); g.warnings.forEach(function (w) { ul.append(el("li", null, w)); }); box.append(ul);
  }
  box.append(el("p", "s", "다 하고 원래 브랜치로 돌아가려면: " + g.back));
}
function save() {
  var st = $("status"); st.textContent = ""; st.className = ""; st.setAttribute("role", "status");
  var missing = pickSteps().filter(function (x) { return !(get(x[0].id, x[1].n) || {}).pick; });
  if (missing.length) {
    st.className = "bad"; st.setAttribute("role", "alert");
    st.append(el("p", null, "아직 고르지 않은 단계 " + missing.length + "개가 있습니다. 모두 고른 뒤에 저장할 수 있습니다."));
    var ul = el("ul");
    missing.forEach(function (x) {
      var b = el("button", "link", x[0].title + " " + x[1].n + "단계로 이동"); b.type = "button";
      b.addEventListener("click", function () { focusStep(x[0].id, x[1].n); });
      var li = el("li"); li.append(b); ul.append(li);
    });
    st.append(ul); focusStep(missing[0][0].id, missing[0][1].n);
    return;
  }
  $("save").disabled = true;
  api("/api/save", {choices: choices}).then(function (r) {
    $("save").disabled = false;
    if (!r.saved) { st.className = "bad"; st.setAttribute("role", "alert"); st.textContent = r.reason || "저장하지 못했습니다."; return; }
    dirty = false; lastSaved = r.changed;
    st.append(el("p", "ok", "저장했습니다: " + r.path + " (정상을 정한 단계 " + r.changed + "개)"));
    if (r.records) st.append(el("p", "warn", "기록만으로 둔 " + r.records + "개 단계는 실행할 때 맞는지 검사하지 않습니다."));
    if (r.backup) st.append(el("p", null, (r.dirty_before ? "저장 전부터 커밋하지 않은 수정이 있어 " : "git이 관리하지 않는 파일이라 ") +
      "저장 전 파일을 " + r.backup + "에 남겼습니다."));
    if (!r.same_format) st.append(el("p", "warn", "원본 파일 형식이 달라 변경 내역(diff)이 커질 수 있습니다."));
    if (r.note) st.append(el("p", null, r.note));
    if (r.errors.length) {
      st.append(el("p", "bad", "파일 형식 검사(validate): 문제 " + r.errors.length + "개. 고친 뒤 올립니다."));
      var ul = el("ul"); r.errors.slice(0, 20).forEach(function (x) { ul.append(el("li", null, x)); }); st.append(ul);
    } else st.append(el("p", null, "파일 형식 검사(validate): 문제 없음"));
    if (r.locked) st.append(el("p", "warn", "파일에서 정해야 하는 단계 " + r.locked + "개가 남아 있어, 이대로는 run과 CI가 거부합니다."));
    showGit(r.git);
    choices = {};
    return api("/api/state").then(function (s) { S = s; render(); }, function () {
      st.append(el("p", "warn", "저장은 했지만 화면을 새로 읽지 못했습니다. 새로 고침(F5)을 누릅니다."));
    });
  }).catch(function (e) {
    $("save").disabled = false; st.className = "bad"; st.setAttribute("role", "alert"); st.textContent = "저장하지 못했습니다: " + e.message;
  });
}
addEventListener("beforeunload", function (e) { if (dirty) { e.preventDefault(); e.returnValue = ""; } });
$("save").addEventListener("click", save);
if (!T) { $("issues").textContent = "토큰이 없습니다. 터미널에 나온 주소로 다시 여세요."; $("save").disabled = true; return; }
api("/api/state").then(function (s) { S = s; render(); }).catch(function (e) {
  $("issues").textContent = "불러오지 못했습니다: " + e.message; $("save").disabled = true;
});
})();
</script></body></html>
"""


def page(nonce: str) -> str:
    return PAGE.replace("__NONCE__", nonce)
