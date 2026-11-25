# gateprobe: AgentCore Gateway 정책 점검

AI 에이전트의 도구 호출을 막는 문지기(Gateway 정책)가 제대로 일하는지 점검하는 도구. 0.4.0까지의 이름은 gwcheck였고, 옛 명령 `gwcheck`도 그대로 동작한다.

Amazon Bedrock AgentCore Gateway에 정해 둔 도구 호출을 모델 없이 보낸다. 각 호출이 허용됐는지, 막혔는지(AWS 권한 또는 Gateway 정책)를 미리 정해 둔 정상 동작과 비교한다. 정책을 바꾼 뒤 막아야 할 호출이 열리거나 정상 호출이 막히지 않았는지 확인하는 용도다. 결과는 HTML 점검 결과서로 나온다.

처음이면 맨 아래 "용어"를 먼저 본다.

- **오프라인 키트**: 저장된 점검 기록으로 결과서를 만들어 보는 연습용 묶음이고, `example/` 폴더가 들어 있다
- **도구**: `gateprobe-<버전>-py3-none-any.whl`. 내 Gateway를 점검하는 설치 파일이다. 설치 파일만 받았으면 2절의 `example/` 폴더는 없다

## 빠른 시작

### 1. 설치

Python 3.10 이상이 필요하다. `python --version`(macOS는 `python3 --version`)으로 확인한다.
설치 파일(.whl)이 있는 폴더에서 실행한다.

```bash
pip install --no-deps gateprobe-0.4.0-py3-none-any.whl
gateprobe --help
```

- 위 명령은 AWS 없이 쓰는 기능(형식 검사, 결과서 만들기)만 설치한다. 인터넷이 필요 없다. AWS에 점검을 보내려면(3절) `--no-deps` 없이 설치한다(boto3를 함께 받는다)
- Windows에서 한글이 깨지면 실행 전에 PowerShell에서 `$env:PYTHONUTF8 = "1"`(cmd는 `set PYTHONUTF8=1`)을 한 번 입력한다
- Windows에서 `pip`나 `gateprobe`를 찾지 못한다고 나오면 `python -m pip install --no-deps ...`처럼 앞에 `python -m`을 붙인다. `python`도 없다고 나오면 `py -m`으로 해 본다. 이렇게 설치했으면 이후에도 `gateprobe` 대신 같은 방식으로 `python -m gateprobe`(또는 `py -m gateprobe`)를 쓴다
- macOS, Linux에서는 가상환경을 먼저 만든다. `python3 --version`이 3.9 이하면 3.10 이상을 새로 설치하고, 아래 `python3` 자리에 `python3.12`처럼 그 버전을 적는다

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --no-deps gateprobe-0.4.0-py3-none-any.whl
  ```

### 2. 예시로 해 보기 (AWS 없이)

오프라인 키트의 `example/` 폴더에 시나리오 파일, 대상 파일, 실제 점검 기록 두 개(`record_A.json`, `record_B.json`)가 있다. 설치한 터미널에서 그대로 실행한다.

```bash
cd example
gateprobe validate --spec scenarios.json --target target.json
gateprobe render --record record_A.json --spec scenarios.json --target target.json --html report_A.html
gateprobe render --record record_B.json --spec scenarios.json --target target.json --html report_B.html
```

- `validate`는 형식 검사다. 마지막 줄이 "오류 0개"면 통과
- `render`는 점검 기록으로 결과서(HTML)를 만든다. "저장: report_A.html"은 결과서를 만들었다는 뜻이고, 정책이 통과했다는 뜻이 아니다. 판정은 결과서 안에 있다
- `example` 폴더에 새로 생긴 `report_A.html`과 `report_B.html`을 각각 브라우저로 연다. 파일을 더블클릭하거나, Windows는 `start report_A.html`, macOS는 `open report_A.html`. 읽는 법은 아래 "결과서 읽는 법"

내 파일로 할 때는 파일 이름만 바꾼다. 점검 기록은 `gateprobe run --execute`가 만든다(3절).

### 3. 내 Gateway에 쓰기 (AWS 필요)

**준비물**
- AWS에 로그인한 터미널(예: `aws login`, SSO를 쓰면 `aws sso login`). 프로필을 여러 개 쓰면 그 이름
- 점검할 Gateway의 이름 또는 ID와 지역(예: ap-northeast-1)
- JWT(토큰) 인증 Gateway면 토큰을 받을 클라이언트의 ID와 비밀값
- 1절에서 `--no-deps`로 설치했으면 `pip install gateprobe-0.4.0-py3-none-any.whl`로 다시 설치(boto3를 받는다)
- 시험용 Gateway와 시험용 데이터(아래 "주의")

**순서** (`init`이 마지막에 보여 주는 "다음 단계"와 같다)

0. JWT Gateway면 클라이언트 정보를 환경 변수로 넣는다. PowerShell:
   ```powershell
   $env:GW_CLIENT_ID = "클라이언트 ID"
   $env:GW_CLIENT_SECRET = "클라이언트 비밀값"
   ```
   macOS·Linux는 `export GW_CLIENT_ID=...`. 비밀값은 파일이나 저장소에 적지 않는다. 화면 공유·녹화 중에는 입력하지 않는다
1. 대상 파일과 시나리오 틀을 만든다
   ```bash
   gateprobe init --gateway <Gateway 이름 또는 ID> --region ap-northeast-1 [--profile 프로필]
   ```
   - `checks/target.json`: 대상 파일. 인증 방식과 MCP 버전도 Gateway 설정에서 읽어 적는다
   - `checks/.gateprobe_vars.json`: Gateway 주소, ARN 등 계정 정보. git에 넣지 않는다(`.gitignore`에 이 파일과 observe 초안 `*_observed.json`을 자동 추가)
   - `checks/scenarios.json`: 도구마다 시나리오 틀. 숫자·선택지 인자는 예시로 채우고, 문자열 인자와 정상(expect)은 TODO
2. 실행 전 진단: `gateprobe doctor --target checks/target.json [--profile 프로필]`. 마지막 줄에 실패·주의 개수와 정책 엔진 모드가 나온다. [실패]는 → 줄대로 고친다
3. `checks/scenarios.json`의 인자 TODO를 채운다. 필요 없는 시나리오는 지운다
4. 지금 결과 보기 (선택이지만 권함):
   ```bash
   gateprobe observe --spec checks/scenarios.json --target checks/target.json --execute
   ```
   초안 `checks/scenarios_observed.json`이 새로 생긴다. 정상이 TODO인 단계마다 `"지금결과": "ALLOW (허용)"`처럼 적혀 있다. 원본은 바뀌지 않는다. 초안은 저장소에 올리지 않는다(`init`이 `.gitignore`에 `*_observed.json`을 넣는다. 직접 만든 저장소면 이 줄을 손으로 넣는다)
5. 정상(expect) TODO를 정한다. 화면으로 하면:
   ```bash
   gateprobe ui --spec checks/scenarios.json --target checks/target.json
   ```
   브라우저에 "정상 확인" 화면이 열린다. 단계마다 지금 결과를 참고해 허용 / 차단 / 기록만 중에서 고르고 "파일로 저장"을 누른다. 원본의 정상 칸만 바뀌고, 바로 형식 검사 결과가 나온다. 파일이 git 저장소 안에 있으면 "GitHub에 올리기" 버튼이 생긴다. 누르면 새 브랜치로 올리고 PR 만들기 페이지를 연다(아래 "정상 확인 화면").
   화면 없이 하려면 원본에서 `"expect": "TODO"`를 `"ALLOW"`, `"POLICY_DENY"` 같은 값으로 직접 바꾸고 `gateprobe validate --spec checks/scenarios.json --target checks/target.json`으로 검사한다
6. 점검: `gateprobe run --spec checks/scenarios.json --target checks/target.json [--profile 프로필] --execute --html report.html`

- 실행 화면은 호출마다 `[일치]`, `[불일치]`, `[확인 필요]`, `[기록만]`과 "정상 …, 결과 …"를 보여 주고, 마지막에 결과서 첫 줄과 같은 결론을 보여 준다
- `--profile`은 대상 파일에 저장하지 않는다. `checks/`를 저장소에 올려 CI에서 쓸 때 내 PC의 프로필 이름이 끼지 않게 하려는 것이다
- JWT Gateway에서 토큰 주소를 찾지 못하면 `init`이 알려 준다. 그때는 토큰을 직접 받아 `GW_TOKEN`에 넣는다
- `observe`는 실제로 호출한다. 삭제·송금 같은 도구도 그대로 실행된다. 보내기 전에 호출할 도구와 횟수를 보여 주고, 정상이 TODO인 단계가 없거나 저장할 파일이 이미 있으면 호출하지 않고 멈춘다
- 정책 엔진이 ENFORCE면 도구 목록에 지금 허용된 도구만 보일 수 있다. 막혀야 할 도구(송금, 삭제 등)는 틀에 없을 수 있으니 직접 시나리오에 넣는다
- 정상을 정하는 일은 사람이 해야 한다. 어떤 호출이 허용되고 막혀야 하는지는 정책을 만든 사람만 안다. 지금 결과를 그대로 정상으로 적으면 잘못된 상태까지 정답이 된다
- `doctor`나 `init`이 "정책 엔진 모드가 LOG_ONLY"라고 알려 주면, 그 정책은 기록만 하고 막지 않는다. 그 상태의 결과를 정상으로 적지 않는다

## 정상 확인 화면 (`gateprobe ui`)

`observe` 초안을 보면서 정상을 고르는 화면이다. 정상은 업무 규칙을 아는 사람이 정해야 하므로 화면은 정상 칸을 미리 채우지 않는다.

- 단계는 세 가지로 보인다
  - **고를 수 있음**: 정상이 TODO이고 지금 결과가 있는 단계. 허용 / 차단 / 기록만(검사 안 함) 중 하나를 고른다. 차단이면 어디서 막혀야 하는지(정책 / 권한(IAM) / 어디서든)도 고른다. 처음 값은 지금 결과와 상관없이 "정책"
  - **잠김**: 인자에 TODO가 남아 호출하지 못한 단계, 지금 결과가 도구 오류나 판정 불가인 단계, Gateway마다 정상이 다른 단계, 초안에 지금 결과가 없는 단계. 이유가 보이고, 파일에서 직접 정한다
  - **정해 둠**: 원본에 정상이 이미 있는 단계. 읽기만 한다. 바꾸려면 파일에서 고치고 PR 변경 내역으로 리뷰한다. 모든 단계가 정해 둠인 시나리오는 화면에서 숨기고 개수만 보여 준다
- 고른 정상이 지금 결과와 다르면 그 단계에 "참고: 지금 결과와 다릅니다"가 나온다. 정책이 틀렸거나 고른 정상이 틀렸을 수 있다. 같아도 정답이라는 뜻은 아니다. 아래 개수는 한 번 보내 본 결과와의 비교라 참고용이다
- 저장하면 원본에서 고른 단계의 `expect`만 바뀐다. 들여쓰기와 줄바꿈은 원본을 따른다. git이 관리하지 않는 파일이면 원래 파일을 `.bak`으로 남긴다(아래 사본 위치 참고)
- observe 뒤에 원본의 인자나 시나리오를 고쳤으면 저장하지 않는다. observe를 다시 돌린다. 화면을 연 뒤 다른 편집기에서 원본을 바꿔도 저장하지 않는다
- 원본에 커밋하지 않은 수정이 있었으면 저장 전 파일을 `.bak`으로 남기고, 그 수정도 같은 커밋에 들어간다고 알려 준다
- 저장 뒤 "GitHub에 올리기"를 누르고 확인하면 화면이 git 명령 네 개를 대신 실행한다: 새 브랜치 `gateprobe/expect-날짜-시각` 만들기, 저장한 파일 추가, 그 파일 하나만 커밋, `origin`에 push. 끝나면 제목과 본문이 채워진 PR 만들기 페이지가 브라우저에 열린다. PR 만들기와 병합은 사람이 GitHub에서 한다. PR을 만들면 CI가 새로 정한 정상으로 지금 정책을 점검한다
  - main에 직접 올리거나 강제로 올리지 않는다. 서버는 화면이 보낸 명령이 아니라 저장할 때 만든 계획만 실행한다
  - 저장할 때의 브랜치에 그대로 있고, 파일이 저장한 그대로이고, git 사용자 이름이 정해져 있고, 같은 이름의 브랜치가 없을 때만 한다. 저장한 뒤 파일을 편집기로 또 고쳤으면 형식 검사를 거치지 않은 내용이라 올리지 않는다
  - 다른 파일의 수정은 커밋에 넣지 않는다. 파일 이름의 `[ ]`, `*`도 글자 그대로 다룬다
  - 버튼 위 "올리기 전에 확인하세요"에 PR에 같이 들어갈 커밋, 저장 전부터 있던 수정, 기본 브랜치가 아닌 브랜치 같은 주의할 점이 나온다. 확인 창에도 같은 내용이 나온다
  - 올린 뒤 이 컴퓨터는 새 브랜치에 있다. 다른 작업이나 다음 정상 확인 전에 화면에 나온 명령으로 원래 브랜치에 돌아간다. PR이 합쳐진 뒤에는 `git pull`로 main을 최신으로 받는다
  - 형식 검사에 문제가 있거나 파일에서 정해야 하는 단계가 남았으면 버튼이 꺼진다. CI가 어차피 거부하기 때문이다
  - push는 로그인 창을 기다리느라 몇 분 걸릴 수 있어 5분까지 기다린다. 그동안 화면은 읽을 수 있고 저장은 막는다. 시간이 넘으면 git과 로그인 도우미를 함께 끝낸다
  - push가 실패하거나 시간이 넘으면 커밋은 새 브랜치에 남기고, 이어서 실행할 push 명령과 돌아가는 명령을 보여 준다. 그 전 단계(브랜치 만들기, 추가, 커밋)가 실패하면 새 브랜치를 지우고 원래 브랜치로 돌아간다(저장한 파일 내용은 그대로)
  - ssh 원격이면 암호 문구를 묻지 않는 모드로 실행한다. ssh-agent에 키가 올라가 있어야 한다
  - 버튼 대신 직접 하려면 "직접 하려면"을 펼쳐 같은 명령 네 줄을 복사해 터미널에서 실행한다. 경로에 명령에 넣기 어려운 글자(따옴표, `$`, `;` 등)가 있으면 명령과 버튼을 만들지 않는다
  - `--no-browser`로 열면 PR 페이지도 자동으로 열지 않고 주소만 보여 준다
- git이 관리하는 저장소 안의 파일이면 저장 전 사본(`.bak`)은 `.git/gateprobe-backup/` 아래에 남긴다. 저장소에 딸려 올라가지 않게 하려는 것이다
- 화면은 이 컴퓨터(127.0.0.1)에서만 열리고 AWS에 접속하지 않는다. 주소에 붙은 토큰은 실행할 때마다 새로 만들고, 화면을 열면 주소창에서 지운다. 다 쓰면 터미널에서 Ctrl+C로 끝낸다

## 결과서 읽는 법

맨 위 **종합 판정**
- **적합**: 정상을 정해 둔 호출이 모두 정상대로 나왔다
- **부적합**: 정상과 다른 호출(불일치)이 있다. 이 정책 변경은 그대로 내보내지 않는다
- **점검 미완료**: 응답으로 허용·거부를 가릴 수 없었거나, 사전 준비가 실패했거나, 정상을 정해 둔 호출이 하나도 없었다. 통과가 아니다

항목별 표의 **정상** 칸은 시나리오를 쓴 사람이 미리 정해 둔 올바른 동작(차단 또는 허용. `scenarios.json`에 적은 기대값), **결과** 칸은 실제로 일어난 일이다. **판정**은 결과가 정상과 같은지다. 좋고 나쁨이 아니다.

| 판정 | 뜻 |
| --- | --- |
| 일치 | 정상대로 차단되거나 허용됐다. 정상이 "IAM 또는 정책 차단"이면 어느 쪽에서 차단돼도 일치 |
| 불일치 | 정상과 다르다. 아래 작은 글씨가 업무 영향: "차단돼야 할 호출이 허용됨", "허용돼야 할 호출이 차단됨", "차단 계층 변경" 등 |
| 확인 필요 | 응답으로 허용·거부를 가릴 수 없거나 사전 준비가 실패했다 |
| 기록만 | 정상을 정해 두지 않고 결과만 남겼다 |

"호출 보기"를 누르면 그 시나리오의 호출 순서와 각 결과가 보인다. 불일치가 있으면 맨 아래 "불일치 호출 상세" 표에 몇 번째 호출이 어떻게 달랐는지와 Gateway가 돌려준 응답이 나온다.

## 확인하는 것과 하지 않는 것

- 확인하는 것: 시나리오에 적은 호출 각각의 결과. 같은 시나리오의 호출은 한 정책 세션으로 보내므로 "민감 데이터를 읽은 뒤 발송 금지" 같은 순서 정책도 확인된다
- 확인하지 않는 것: 모델이 실제로 그런 호출을 할지, 시나리오에 없는 호출. 결과는 시나리오를 얼마나 잘 썼는지에 달려 있다
- 지원: IAM(SigV4) 인증 Gateway, JWT 인증 Gateway(클라이언트 ID·비밀값을 환경 변수로, gateprobe가 토큰을 받음). CI 예시는 IAM 인증만 다룬다

## 주의

- **운영 Gateway에 쓰지 말 것.** 허용된 호출은 실제로 도구를 실행한다(삭제, 발송 등). 시험용 Gateway를 쓰고, Gateway 뒤의 Lambda, S3 같은 백엔드도 시험용이어야 한다
- 도구 응답이 성공·실패를 어떻게 알리는지는 도구마다 다르다. 기본 분류 규칙은 응답에 오류 표시나 거부 문구가 없으면 허용으로 본다. `{"ok": false}`처럼 자기 형식으로 실패를 알리는 도구는 대상 파일의 `classify` 규칙을 맞춰야 한다(아래)
- GitHub CI에 연결하면 PR 코드가 AWS 역할 자격 증명으로 실행된다. 저장소에 쓰기 권한이 있는 사람은 신뢰한다는 전제다. CI 역할 권한은 시험용 정책 엔진과 Gateway로만 좁힌다

## 파일 형식

**대상 파일** (`init`이 만든다)

```json
{
  "name": "my-gw",
  "region": "ap-northeast-1",
  "auth": {"type": "sigv4"},
  "vars_file": ".gateprobe_vars.json",
  "gateways": {"my-gw": "{gateway_url}"},
  "labels": {"my-gw": "시험용 Gateway"},
  "tool_labels": {"read_file": "읽기"},
  "classify": {"rules": [{"when": {"path": "ok", "equals": false}, "then": "TOOL_ERROR"}], "default": "ALLOW"}
}
```

- `auth`: `{"type": "sigv4"}`(IAM 인증), `{"type": "oauth", "token_url": "...", "client_id_env": "GW_CLIENT_ID", "client_secret_env": "GW_CLIENT_SECRET", "scope": "선택"}`(gateprobe가 토큰을 받음), `{"type": "bearer", "token_env": "GW_TOKEN"}`(토큰을 직접 넣음)
- `mcp_version`: `"2026-07-28"`(기본) 또는 `"2025-11-25"`. Gateway가 받는 버전이어야 한다. 아니면 HTTP 400 "Unsupported protocol version"이 나고 gateprobe가 고칠 값을 알려 준다. `2025-11-25`만 받으면서 세션(initialize)까지 요구하는 Gateway는 아직 지원하지 않는다
- `gateways` 값에는 주소, `{변수}`, `env:환경변수`를 쓸 수 있다. 계정 정보는 `vars_file`(git에 넣지 않음)에 둔다
- `labels`, `tool_labels`: 결과서에 보일 이름
- `classify`: 도구 결과를 나누는 규칙. 위에서부터 처음 맞는 규칙을 쓴다. 조건: `is_error`, `path` + `equals` / `in` / `matches` / `exists`, `text_matches`
- `inject_args`: 모든 호출 인자에 붙일 값

**시나리오 파일**

```json
{
  "name": "티켓 도구 점검",
  "target": "ticket-tools",
  "분류": {"유출 차단": "민감 데이터를 읽은 뒤 밖으로 보내면 막혀야 한다"},
  "scenarios": [
    {"id": "export_external", "제목": "외부로 내보내기", "요약": "외부 주소로 내보내면 막혀야 함", "분류": "유출 차단",
     "steps": [{"tool": "export_tickets", "args": {"destination": "https://x/{run}"}, "expect": "POLICY_DENY"}]}
  ]
}
```

- `target`은 Gateway target 이름이다. 도구 `export_tickets`는 `ticket-tools___export_tickets`로 호출된다
- 기대값: `"ALLOW"`, `["IAM_DENY", "POLICY_DENY"]`(어느 쪽으로 막혀도 됨), `{"outcome": "POLICY_DENY", "policy": "정규식"}`(거부한 정책 ID까지), Gateway별 `{"이름": ..., "*": 나머지}`. 응답 자체가 거부되는 경우(예: 세션 헤더 누락)는 `{"outcome": "UNKNOWN", "error": "정규식"}`
- `제목`, `요약`, `분류`: 결과서에 그대로 나온다. 파일 맨 위 `분류`에 묶음 설명을 적는다
- 단계별 `session`: 이름(같은 이름은 같은 세션), `{"omit": true}`(헤더 없이), `{"raw": 값}`
- 자동 변수: `{run}` 시나리오마다 새 ID, `{ns}`, `{call}` 호출마다 새 ID, `{gateway}`
- `fixtures`: 시나리오마다 S3에 새로 올리는 객체

## 결과 분류

| 결과 | 뜻 |
| --- | --- |
| ALLOW | 도구가 실행되고 성공 |
| IAM_DENY | 도구는 실행됐지만 백엔드 권한이 거부 |
| POLICY_DENY | Gateway 정책 엔진이 거부 (JSON-RPC -20001) |
| TOOL_ERROR | 그 밖의 도구 오류 |
| UNKNOWN | 전송 오류, 정책 거부가 아닌 JSON-RPC 오류, Gateway 내부 오류 |

정책 엔진을 붙인 Gateway의 역할에 `bedrock-agentcore:GetWorkloadAccessToken` 권한이 없으면 모든 호출이 "An internal error occurred"로 끝났다(시험한 설정에서). 이 경우는 판정 불가로 둔다.

## 명령과 종료 코드

```bash
gateprobe init --gateway <ID|이름> --region <리전>       # 대상 파일, 변수 파일, 시나리오 틀 만들기
gateprobe doctor --target T.json                         # 실행 전 진단 (자격 증명·토큰, 접속, MCP 버전, 정책 엔진 모드)
gateprobe observe --spec S.json --target T.json --execute   # 기대값 TODO 옆에 '지금 결과'를 적은 초안 (새 파일)
gateprobe tools --target T.json --gateway <이름>         # 도구 이름과 인자 확인
gateprobe validate --spec S.json --target T.json         # 형식 검사, AWS 접속 없음
gateprobe run --spec S.json --target T.json              # 계획만 출력
gateprobe run --spec S.json --target T.json --execute --html report.html --junit out.xml --summary out.md
gateprobe render --record record.json --spec S.json --target T.json --html report.html   # 기록으로 결과서 다시 만들기
```

종료 코드: 0 적합, 1 부적합(정상과 다른 허용/차단), 2 점검 미완료(판정 불가, 사전 준비 실패, 정상을 정한 호출 0개), 3 설정 오류(형식, TODO, 파일 없음, 자격 증명·토큰 없음).
1과 2를 나눈 이유: 접속 문제를 정책 회귀로 잘못 보고하지 않으려고.

CI 예시는 `examples/ci/`에 있다.

## 용어

| 용어 | 뜻 |
| --- | --- |
| Gateway | AI 에이전트가 도구(파일 읽기, 공지 발송 등)를 부를 때 거치는 AWS의 관문. 여기서 정책을 적용한다 |
| 정책 엔진, 정책 | Gateway에 붙어 호출마다 허용·차단을 정하는 규칙 묶음(Cedar, 시간·순서 조건은 Dogwood라는 정책 언어로 쓴다) |
| ENFORCE / LOG_ONLY | 정책 엔진 모드. ENFORCE는 실제로 막고, LOG_ONLY는 기록만 하고 막지 않는다 |
| IAM 차단 / 정책 차단 | IAM 차단은 도구 뒤의 AWS 권한이 거부한 것, 정책 차단은 Gateway 정책이 도구에 가기 전에 거부한 것 |
| 세션 | 앞선 호출의 기록을 묶는 단위. "민감 문서를 읽은 뒤 1시간 안에는 공지 금지" 같은 조건은 같은 세션 안에서만 본다. gateprobe는 시나리오 하나를 세션 하나로 보낸다 |
| MCP | AI 에이전트가 도구를 부르는 약속(프로토콜). 버전이 둘 있어 Gateway가 받는 버전으로 보내야 한다 |
| JWT, 토큰 | 로그인 대신 쓰는 짧은 출입증. JWT 인증 Gateway는 이 토큰이 있어야 부를 수 있다 |
| 정상 | 시나리오를 쓴 사람이 미리 정한 올바른 동작(차단 또는 허용). 파일에서는 `expect` 칸 |

## 시험

```bash
python -m gateprobe.test_gateprobe      # AWS 없이 가짜 Gateway로
```
