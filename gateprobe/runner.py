"""시나리오를 Gateway마다 실행하고 기대와 비교한다. 접속 객체를 밖에서 받아 AWS 없이도 시험할 수 있다."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone

from gateprobe.classify import classify
from gateprobe.spec import describe, error_text, expectation, fill, matches, rid, tool_name


def _body(fx, spec_dir):
    if "body" in fx:
        return fx["body"]
    for base in (spec_dir, os.getcwd()):
        path = fx["body_file"] if os.path.isabs(fx["body_file"]) else os.path.join(base, fx["body_file"])
        if os.path.exists(path):
            return open(path, encoding="utf-8").read()
    raise FileNotFoundError(fx["body_file"])


def s3_putter(profile, region):
    import boto3

    s3 = boto3.Session(profile_name=profile, region_name=region).client("s3")
    return lambda bucket, key, body: s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))


def run(spec, target, gateways, make_client, put_fixture=None, spec_path=None, log=print):
    """기록(dict)을 돌려준다. 요약: record["summary"] = {calls, checked, passed, regressions, unknown, fixture_errors}."""
    spec_dir = os.path.dirname(os.path.abspath(spec_path)) if spec_path else os.getcwd()
    record = {"tool": "gateprobe", "spec": spec.get("name"), "target": target.name,
              "spec_sha256": hashlib.sha256(open(spec_path, "rb").read()).hexdigest() if spec_path else None,
              "classify_sha256": hashlib.sha256(json.dumps(target.classify, sort_keys=True).encode()).hexdigest(),
              "created_utc": datetime.now(timezone.utc).isoformat(), "configs": {}}
    s = {"calls": 0, "checked": 0, "passed": 0, "regressions": 0, "unknown": 0, "fixture_errors": 0}
    for gw in gateways:
        client = make_client(gw)
        rows = []
        for sc in spec["scenarios"]:
            variables = {**target.vars, "run": rid(), "ns": rid(12), "gateway": gw}
            fixture_error = None
            for fx in spec.get("fixtures", []):
                try:
                    put_fixture(fill(fx["bucket"], variables), fill(fx["key"], variables), fill(_body(fx, spec_dir), variables))
                except Exception as exc:   # 사전 객체가 없으면 이 시나리오는 판정하지 않는다
                    fixture_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                    break
            if fixture_error:
                s["fixture_errors"] += 1
                rows.append({"scenario": sc["id"], "step": 0, "tool": "(fixtures)", "expected": None, "observed": "UNKNOWN",
                             "match": None, "error": fixture_error})
                log(f"!! {gw:6s} {sc['id']:28s} 사전 객체 실패: {fixture_error}")
                continue
            sessions = {}   # 시나리오 안의 세션 이름 -> 세션 ID. 이름을 안 쓰면 모두 "main" 하나
            for i, st in enumerate(sc["steps"], 1):
                if st.get("wait"):   # 앞 호출의 기록이 정책 엔진에 보이기까지, 또는 시간 조건(예: 5분 뒤)을 위해 기다린다
                    time.sleep(float(st["wait"]))
                variables["call"] = uuid.uuid4().hex
                args = {**fill(st.get("args", {}), variables), **fill(target.inject_args, variables)}
                session_id, session_label = step_session(st.get("session"), sessions)
                obs = client.call(tool_name(spec, st["tool"]), args, session_id)
                seen = classify(obs, target.classify)
                exp = expectation(st.get("expect"), gw)
                ok = matches(exp, seen, obs.get("policy_id"), error_text(obs))
                s["calls"] += 1
                if exp is not None:
                    s["checked"] += 1
                    s["passed"] += ok is True
                    if ok is False:
                        s["unknown" if seen == "UNKNOWN" else "regressions"] += 1
                out = obs.get("output") or {}
                rows.append({"scenario": sc["id"], "step": i, "tool": st["tool"], "session": session_label,
                             "expected": describe(exp) if exp else None,
                             "observed": seen, "match": ok, "kind": obs.get("kind"), "status": out.get("status"),
                             "error_code": out.get("error_code"), "denying_policy_id": obs.get("policy_id"),
                             "rpc_code": obs.get("rpc_code"), "http_status": obs.get("http_status"),
                             "rpc_message": obs.get("rpc_message"), "detail": obs.get("detail"), "hint": obs.get("hint"),
                             # 도구 오류로 분류된 호출의 문구(isError든, {"error": ...} 같은 자기 형식이든). 업무 오류인지 인프라 오류인지
                             # 사람이 가릴 수 있게 남긴다. 성공 결과 본문은 남기지 않는다
                             "tool_text": (obs.get("text") or "")[:300] or None if (obs.get("is_error") or seen == "TOOL_ERROR") else None})
                from gateprobe.view import SHORT, expected_text   # 결과서와 같은 낱말 (검토 11-23)
                mark = "기록만" if ok is None else ("일치" if ok else ("확인 필요" if seen == "UNKNOWN" else "불일치"))
                want = expected_text(describe(exp)) if exp else "-"
                log(f"[{mark}] {gw} {sc['id']} {i}단계 {st['tool']}: 정상 {want}, 결과 {SHORT.get(seen, seen)}")
        record["configs"][gw] = rows
    record["summary"] = s
    return record


def step_session(value, sessions):
    """단계의 session 값 -> (보낼 세션 ID 또는 None, 기록용 이름).
    없음: 시나리오 기본 세션("main")   "이름": 시나리오 안에서 이름마다 새 세션
    {"omit": true}: 헤더를 보내지 않음   {"raw": "값"}: 헤더 값을 그대로 보냄 (빈 값, 긴 값, 허용 밖 문자 시험)"""
    if value is None:
        value = "main"
    if isinstance(value, str):
        if value not in sessions:
            sessions[value] = str(uuid.uuid4())
        return sessions[value], value
    if value.get("omit"):
        return None, "(헤더 없음)"
    raw = str(value["raw"])
    return raw, f"(raw {len(raw)}자)"


MEANING_KO = {"ALLOW": "허용", "IAM_DENY": "IAM 차단", "POLICY_DENY": "정책 차단", "TOOL_ERROR": "도구 오류", "UNKNOWN": "판정 불가"}


def _has_todo(x):
    return "TODO" in json.dumps(x, ensure_ascii=False)


def _todo_expect(st):
    return st.get("expect") is None or _has_todo(st.get("expect"))


def observe_plan(spec):
    """observe가 보낼 호출을 미리 정한다 (호출 전에 사람에게 보여 주려고, 외부 검토 11-23).
    기대값 TODO가 없는 시나리오는 건너뛰고, 시나리오 안에서는 마지막 TODO 단계까지만 보낸다(앞 단계는 순서 정책 때문에 필요).
    인자에 TODO가 남은 단계에서 그 시나리오를 멈춘다. 반환: [{"id", "calls": [(단계, 도구)], "todo", "skipped"}]"""
    plan = []
    for sc in spec.get("scenarios", []):
        steps = sc.get("steps", [])
        todo_idx = [i for i, st in enumerate(steps, 1) if _todo_expect(st)]
        if not todo_idx:
            continue
        calls, skipped = [], 0
        for i, st in enumerate(steps[:max(todo_idx)], 1):
            if _has_todo(st.get("args", {})) or _has_todo(st.get("tool", "")):
                skipped = sum(1 for j in todo_idx if j >= i)
                break
            calls.append((i, st["tool"]))
        plan.append({"id": sc["id"], "calls": calls, "todo": len(todo_idx), "skipped": skipped})
    return plan


def observe(spec, target, gateway, client, log=print, put_fixture=None, spec_path=None):
    """기대값이 TODO인 단계를 실제로 한 번 호출해, 그 단계에 "지금결과"를 적은 새 시나리오를 돌려준다.
    기대값은 "TODO" 그대로 둔다(정답으로 굳히지 않으려고). 사람이 지금결과를 보고 맞으면 그 값을, 아니면 정상값을 적어야
    validate와 run이 통과한다. 한 시나리오는 run과 같이 한 정책 세션으로 보낸다.
    사전 객체(fixtures)도 run과 같이 시나리오마다 먼저 올린다. 안 올리면 읽기가 실패한 상태의 결과가 '지금 결과'로 적힌다 (11-25 발견)."""
    out = json.loads(json.dumps(spec))
    counts = {"observed": 0, "skipped": 0, "calls": 0}
    plan = {p["id"]: p for p in observe_plan(spec)}
    spec_dir = os.path.dirname(os.path.abspath(spec_path)) if spec_path else os.getcwd()
    for sc in out.get("scenarios", []):
        p = plan.get(sc["id"])
        if not p:
            continue
        call_steps = {i for i, _ in p["calls"]}
        variables = {**target.vars, "run": rid(), "ns": rid(12), "gateway": gateway}
        fixture_error = None
        if put_fixture and p["calls"]:
            for fx in spec.get("fixtures", []):
                try:
                    put_fixture(fill(fx["bucket"], variables), fill(fx["key"], variables), fill(_body(fx, spec_dir), variables))
                except Exception as exc:
                    fixture_error = f"{type(exc).__name__}: {str(exc)[:120]}"
                    break
        if fixture_error:
            for st in sc.get("steps", []):
                if _todo_expect(st):
                    st["expect"], st["지금결과"] = "TODO", f"호출 안 함 (사전 객체를 올리지 못함: {fixture_error})"
                    counts["skipped"] += 1
            log(f"!! {sc['id']} 사전 객체 실패: {fixture_error}")
            continue
        sessions = {}
        for i, st in enumerate(sc.get("steps", []), 1):
            todo_exp = _todo_expect(st)
            if i not in call_steps:
                if todo_exp:
                    st["expect"], st["지금결과"] = "TODO", "호출 안 함 (이 단계나 앞 단계의 인자에 TODO가 남음)"
                    counts["skipped"] += 1
                continue
            if st.get("wait"):
                time.sleep(float(st["wait"]))
            variables["call"] = uuid.uuid4().hex
            args = {**fill(st.get("args", {}), variables), **fill(target.inject_args, variables)}
            session_id, _ = step_session(st.get("session"), sessions)
            obs = client.call(tool_name(spec, st["tool"]), args, session_id)
            counts["calls"] += 1
            seen = classify(obs, target.classify)
            if todo_exp:
                st["expect"], st["지금결과"] = "TODO", f"{seen} ({MEANING_KO[seen]})"
                counts["observed"] += 1
            log(f"[{'관찰' if todo_exp else '앞 단계'}] {sc['id']} {i}단계 {st['tool']}: 지금 결과 {MEANING_KO[seen]} ({seen})")
    return out, counts


def exit_code(summary):
    """0 모두 기대대로, 1 기대와 다른 허용/거부(회귀), 2 점검 미완료(판정 불가, 사전 객체 실패, 기대값 있는 호출 0개)."""
    if summary["regressions"]:
        return 1
    if summary["unknown"] or summary["fixture_errors"] or not summary["checked"]:
        return 2
    return 0
