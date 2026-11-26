# Tether 사용 안내

회사 GPU 서버의 자체 모델(qwen3.5)로 저장소 작업을 맡기는 방법입니다. 작업은 내 Mac이 아니라 서버의 격리된 샌드박스에서 실행되고, 끝나면 답변과 변경분(패치)을 받아 봅니다.

```
나: tether job request ─▶ 관리자 승인 ─▶ tether job run ─▶ 서버 샌드박스에서 실행 ─▶ 답변·패치 조회
```

## 직원용

### 1. 처음 한 번: 설치와 설정

**관리자에게 받을 것**(공개 채널이나 메일 말고 직접 전달):
- 내 이름으로 된 폴더 하나: 개인 인증서와 키(`cert.pem`, `key.pem`), 서버 확인용 인증서(`service-ca.crt`), 접속 설정(`tether.json`). 키가 곧 내 신원이니 다른 사람에게 주지 마세요.
- `tether-0.1.0.pkg`: 설치 파일

```bash
sudo installer -pkg tether-0.1.0.pkg -target /    # 서명되지 않은 패키지라 더블클릭 대신 터미널로
tether setup ~/Downloads/<받은 폴더>               # 인증서를 ~/.tether에 넣고 설정을 저장한 뒤 로그인까지 확인
#  Logged in as <내 이름> (client certificate).
```
끝나면 받은 폴더는 지워도 됩니다. 회사 네트워크 안에서만 됩니다.
이후 로그인은 자동으로 갱신되므로 다시 할 필요가 없습니다.

### 2. 작업 요청

저장소 폴더 안에서 실행하면 그 저장소(origin)로 요청합니다.
```bash
cd ~/work/some-repo
tether job request --task "README.md를 읽고 설치 절차를 INSTALL.md로 정리해줘"
#  0f3c2a9e-...  pending  README.md를 읽고 ...
```

| 옵션 | 뜻 |
|---|---|
| `--task "..."` 또는 `--task-file 파일` | 할 일. 길면 파일로(`-`는 표준 입력) |
| `--name 이름` | 목록에 보일 이름(기본: 할 일의 첫 줄) |
| `--repo URL` | 다른 저장소(기본: 지금 폴더의 origin) |
| `--every 분` | 정해진 간격으로 반복 실행(최소 15분) |
| `--max-runtime 초` | 한 번 실행의 최대 시간(기본 3600, 최대 14400) |

요청한 뒤 관리자에게 승인을 부탁하세요. 할 일 내용이 바뀌면 새로 요청해야 합니다(승인은 그 내용에 대해 받은 것이기 때문입니다).

### 3. 실행과 결과

```bash
tether job list                  # 내 작업과 상태(pending / approved / rejected / disabled)
tether job run 0f3c              # 승인된 작업 실행. 끝날 때까지 기다렸다가 답변을 보여줌
tether job result 0f3c           # 가장 최근 실행의 답변
tether job result 0f3c --diff > change.patch && git apply change.patch   # 변경분을 내 저장소에 적용
tether job result 0f3c --log     # 실패했을 때: 에이전트 로그의 끝부분
tether job show 0f3c             # 작업 내용과 실행 기록
```
- 답변 끝에는 바뀐 파일 목록이 붙습니다(`M` 수정, `??` 새 파일). 내용은 `--diff`로 봅니다.
- 작업 id는 앞 몇 글자만 써도 됩니다.
- `run`에서 Ctrl-C를 누르면 기다리기만 멈춥니다. 실행은 계속되고, 나중에 `result`로 볼 수 있습니다.
- 에이전트는 GitHub에 push하지 못합니다. 변경분은 `--diff`로 받아서 직접 검토하고 커밋하세요.

### 알아 둘 점
- **쓸 수 있는 저장소:** 지금은 `nugulhie` 조직의 공개 저장소만 됩니다(비공개 저장소는 GitHub App을 만든 뒤에 됩니다).
- **에이전트가 할 수 있는 것:** 저장소 사본 안에서 파일 읽기·쓰기, 셸 명령. 인터넷은 github.com, pypi.org, npm 레지스트리만. 그 밖의 외부 접속과 외부 AI 서비스는 막혀 있습니다.
- **기록:** 모델에 보낸 내용과 받은 답, 실행 결과는 암호화되어 90일 보관됩니다. 관리자는 조사가 필요할 때 사유를 남기고 열람할 수 있고, 그 열람도 기록됩니다.
- **막히는 요청:** 비밀번호·키 같은 비밀 정보나 개인정보가 들어간 지시는 자동 차단됩니다.
- **노트북 분실·퇴사:** 바로 관리자에게 알려 주세요. 인증서를 폐기하면 그 인증서로는 더 이상 접속할 수 없습니다.
- `tether claude`, `tether codex`는 이 환경에서 쓸 수 없습니다.

### 문제 해결
| 메시지 | 원인과 조치 |
|---|---|
| `cannot reach https://192.168.1.27 ...` | 회사 네트워크 밖이거나 서버가 꺼짐 |
| `certificate required` / `certificate revoked` | 폐기되었거나 만료(90일)됨. 관리자에게 새 폴더를 받아 `tether setup`을 다시 |
| `job is pending, not approved` | 아직 승인 전 |
| `this job is already running` | 같은 작업이 실행 중. 끝난 뒤 다시 |
| `agents may only work on repositories in the ... organization` | 허용된 조직의 저장소가 아님 |

## 관리자용

### 직원 관리 (관리자 Mac)
```bash
TETHER_SERVER=https://192.168.1.27 TETHER_MODEL=qwen3.5:122b bash infra/pki/tether-pki.sh user <이름>
#   -> ~/.tether-pki/users/<이름>/ 폴더(90일)를 통째로, agent-launcher/build/tether-0.1.0.pkg 와 함께 직접 전달
bash infra/pki/tether-pki.sh revoke <이름>     # 퇴사·분실
bash infra/staging/60-tls.sh soldoc@192.168.1.27 192.168.1.27 && ssh soldoc@192.168.1.27 docker restart infra-tls-front-1
```
설치 파일은 `cd agent-launcher && ./packaging/build-macos.sh`로 다시 만들 수 있습니다.

### 작업 승인과 운영
```bash
tether job list --status pending                 # 승인 대기 (관리자는 모든 사람의 작업이 보임)
tether job show <id>                             # 할 일 내용을 읽고
tether job approve <id> --reason "검토함"          # 또는 reject / disable (사유는 감사 기록에 남음)
tether job result <id>                           # 관리자는 모든 작업의 결과를 볼 수 있음(열람 기록됨)
```
- 관리자가 혼자라 자기 작업도 승인할 수 있고, 그 사실은 기록(`self_approved`)에 남습니다.
- 정책 변경: `infra/staging/policies/staging.yaml` 수정 → `bash infra/staging/80-publish-policies.sh soldoc@192.168.1.27`
- 내용 암호화 키 교체: 서버 `infra/.env`에 `CONTENT_ENCRYPTION_KEYS=<새 id>:<새 키>,default:<기존 CONTENT_ENCRYPTION_KEY 값>`을 넣고 `30-control-plane.sh` → `docker compose -f infra/docker-compose.yml -f infra/staging/compose.staging.yml exec policy-api python -m app.rekey` → `GET /v1/admin/audit/content/keys`에서 `default`가 `removable`이면 목록에서 뺍니다. 옛 키를 먼저 빼면 그 키로 저장된 내용은 읽을 수 없습니다(`missing`에 표시).
- 긴급 중단(실행 중인 세션 종료와 샌드박스 삭제): 인증서로 토큰을 받아 `POST https://192.168.1.27/v1/admin/revoke`에 `{"user_id":"<이름>","reason":"..."}` (또는 `job_id`, `all`)

### 정기 점검
- 백업: Mac에서 매일 12:30 자동(`~/TetherBackups/backup.log`). 이상하면 macOS 알림
- 서버 재부팅 뒤: `sudo bash infra/staging/90-firewall.sh apply` → 새 SSH 세션에서 `confirm`
- 인증서 만료: 직원 인증서 90일, CRL 365일. 만료 전에 재발급과 `60-tls.sh`
- `~/.tether-pki`는 오프라인 매체에 사본을 둡니다(이 Mac에만 있는 키)
