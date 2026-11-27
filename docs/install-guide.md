# Tether 설치 안내서

고객사 서버 한 대에 Tether를 설치하는 절차입니다. 서버 관리자가 이 문서만 보고 하루 안에 끝낼 수 있게 썼습니다. 설치 프로그램이 무엇을 하는지는 [설치 프로그램 설계](install-design.md)에, 설치한 뒤의 백업·업그레이드·복구는 [운영 문서](operations.md)에 있습니다.

## 0. 받는 것
| 파일 | 내용 |
|---|---|
| `tether-<버전>.tar` | 설치 묶음(이미지, OpenShell, 설치 프로그램). 인터넷 없이 설치됩니다 |
| `tether-<버전>.tar.sha256` | 묶음의 SHA-256 |
| `tether-<버전>.tar.sha256.sig` | 위 파일에 대한 저희 서명 |
| `release-key.pub` | 서명 확인용 공개키 |
| 직원용 설치 파일(`.pkg`) | 직원 Mac에 까는 명령줄 도구 `tether` |

**릴리스 키 지문**입니다. 이 문서로 받은 값과 맞춰 봅니다. 묶음과 같은 경로로 온 값은 믿지 마세요.
```
51866508be4d844c9c3ac388f66fd18dac2ba16d058c5382ae30c8ed8820cabd
```

## 1. 준비
**서버**
- Ubuntu 24.04 LTS, x86_64
- CPU 4개 이상, 메모리 8 GiB 이상, Docker 저장 위치에 빈 공간 30 GiB 이상
- 시간 동기화(NTP). 인증서와 로그인 토큰의 만료 시각이 서버 시계에 달려 있습니다.
- 고정 IP 주소. 직원 PC가 이 주소의 443 포트로 접속합니다. 443을 다른 프로그램이 쓰고 있으면 안 됩니다.

**미리 설치할 것**(설치 프로그램은 점검만 하고 직접 설치하지 않습니다)
- Docker Engine 28 이상과 `docker compose` 플러그인. 회사 미러나 Docker 공식 apt 저장소에서 설치합니다.
- 자체 모델을 쓸 경우: NVIDIA 드라이버, Container Toolkit, OpenAI 호환 추론 엔진(예: Ollama).
  - 엔진은 **127.0.0.1에만** 열고, root가 아닌 계정으로 돌립니다.
  - 바깥에 열려 있으면 설치가 멈춥니다.

**USB 메모리 하나**
- 정책 서명 개인키를 담습니다. 이 키는 서버에 남지 않고, 정책을 바꿀 때만 꽂습니다.
- 잃어버리면 정책을 바꿀 수 없으니 사본을 금고에 둡니다.

**사무실 네트워크에서 SSH로 접속**
- 설치가 끝나면 방화벽이 SSH와 443을 사무실 대역에서만 받습니다.
- 대역 밖에서 접속한 상태면 설치 프로그램이 방화벽 적용을 거부합니다.

## 2. 묶음 확인(풀기 전에)
파일을 서버의 한 디렉터리에 옮긴 뒤 실행합니다.
```bash
openssl pkey -pubin -in release-key.pub -outform DER | sha256sum     # 0절의 지문과 같은지 확인
openssl pkeyutl -verify -pubin -inkey release-key.pub -rawin \
  -in tether-<버전>.tar.sha256 -sigfile tether-<버전>.tar.sha256.sig  # Signature Verified Successfully
sha256sum -c tether-<버전>.tar.sha256                                # tether-<버전>.tar: OK
tar -xf tether-<버전>.tar
```
- 셋 중 하나라도 다르면 **풀지 말고** 저희에게 연락하세요.
- 설치 프로그램도 시작할 때 묶음 안의 모든 파일을 다시 검증합니다.

## 3. 설정 파일 작성
고객사가 채우는 파일은 `/etc/tether/tether.conf` 하나입니다. 비밀 값은 넣지 않습니다. API 키는 파일 경로로 적습니다.
```bash
sudo install -D -m 644 tether-<버전>/install/tether.conf.example /etc/tether/tether.conf
sudo nano /etc/tether/tether.conf
```
| 항목 | 넣을 값 |
|---|---|
| `RELEASE_KEY_SHA256` | 0절의 지문. 묶음의 공개키가 이 값과 다르면 설치하지 않습니다 |
| `TETHER_ADDRESS` | 직원이 접속할 이 서버의 IP 주소 |
| `TETHER_HOSTNAME` | DNS 이름. 없으면 비웁니다 |
| `AUTH_MODE` | `mtls`(개인 인증서 로그인). 이 버전은 이것만 지원합니다 |
| `TETHER_ADMIN_USERS` | 관리자 이름(쉼표로 구분). 5절에서 이 이름으로 인증서를 발급합니다 |
| `SINGLE_ADMIN_APPROVAL` | 관리자가 한 명뿐이면 `1`(자기 작업도 승인할 수 있고, 기록에 남습니다). 아니면 `0` |
| `GITHUB_ORG` | 에이전트가 작업할 GitHub 조직 |
| `LOCAL_INFERENCE_PORT` | 자체 모델 엔진의 포트(예: Ollama `11434`). 없으면 비웁니다 |
| `ANTHROPIC_API_KEY_FILE`, `OPENAI_API_KEY_FILE` | 회사 API 키가 든 파일 경로(6절). 없으면 비웁니다 |
| `CONTENT_RETENTION_DAYS` | 프롬프트와 응답을 보관할 기간(기본 90일) |
| `POLICY_SIGNING_KEY_EXPORT` | USB에 만들 새 파일 경로(예: `/mnt/usb/policy-signing.key`). 이미 있는 파일이면 거부합니다 |
| `FIREWALL` | `on`(권장) |
| `ADMIN_NETWORKS` | SSH와 443을 허용할 대역(예: `10.0.0.0/24,10.0.5.0/24`). 비우면 `TETHER_ADDRESS`가 속한 대역입니다 |

## 4. 설치
USB를 꽂고 마운트한 뒤 실행합니다.
```bash
sudo ./tether-<버전>/install/tether-install /etc/tether/tether.conf
```
설치 프로그램은 10단계를 차례로 출력합니다: 검증, 사전 점검, 이미지, 비밀, 인증서, 정책 서명 키, OpenShell, 제어부, 방화벽, 자기 점검. 보통 몇 분이면 끝납니다.

**실패하면**
- 설치 프로그램이 멈추고 `[FAIL] step N: ...`와 되돌리는 방법을 출력합니다.
- 원인을 고친 뒤 같은 명령을 다시 실행합니다. 이미 끝난 단계는 같은 결과를 내고, 만들어 둔 비밀과 키는 덮어쓰지 않습니다.

**방화벽 확인**
- 9단계가 끝나면 5분 안에 **새 SSH 창을 열어** 아래 명령을 실행합니다.
  ```bash
  sudo /opt/tether/current/tether-install confirm-firewall
  ```
- 하지 않으면 방화벽이 스스로 풀립니다. 잘못된 설정 때문에 서버에 들어갈 수 없게 되는 것을 막기 위해서입니다.

**정책 서명 키**
- 설치가 끝나면 USB를 빼서 보관합니다.
- `tether-doctor`는 서버 안에서 그 키를 찾으면 실패로 봅니다.

끝에 `Tether <버전> is installed.`가 나오면 설치가 끝난 것입니다. 점검은 언제든 다시 할 수 있습니다.
```bash
sudo tether-doctor          # 실패 0이어야 합니다. 경고는 내용을 읽고 판단합니다
```

## 5. 관리자와 직원 등록
**인증서 발급**(서버에서, 사람마다 한 번)
```bash
sudo tether-admin user <이름>          # 90일. 기간을 바꾸려면: sudo tether-admin user <이름> 180
```
- `/etc/tether/pki/ca/users/<이름>/`에 폴더가 생깁니다. 개인 인증서와 키, 서버 확인용 인증서, 접속 설정이 들어 있습니다.
- `TETHER_ADMIN_USERS`에 적은 관리자부터 발급합니다.
- 폴더는 그 사람에게 **직접** 전달합니다(USB 또는 대면). 메일이나 메신저로 보내지 마세요. 키가 곧 그 사람의 신원입니다.
- 전달한 뒤 서버의 폴더는 지워도 됩니다. 다시 필요하면 새로 발급합니다.

**직원 Mac 설정**(각자)
```bash
sudo installer -pkg <직원용 설치 파일>.pkg -target /
tether setup <받은 폴더>                # "Logged in as <이름>"이 나오면 끝
```
- 직원에게는 [사용 안내](usage.md)의 "직원용" 부분을 보여 주세요.
- 관리자도 같은 도구로 작업을 승인합니다(`tether job list --status pending`, `tether job approve <id> --reason ...`).

**퇴사, 노트북 분실**
```bash
sudo tether-admin revoke <이름>         # 인증서 폐기. 출력에 나오는 대로 실행 중인 세션도 끝냅니다
```

## 6. 외부 모델 API 키(선택)
Claude Code와 Codex를 쓰려면 회사 API 키를 서버에 파일로 둡니다. 키는 직원 PC나 샌드박스로 전달되지 않고, 서버의 LLM 게이트웨이만 씁니다.
```bash
sudo sh -c 'umask 077; cat > /etc/tether/secrets/anthropic.key'   # 키를 붙여 넣고 Ctrl-D
```
- `tether.conf`에 `ANTHROPIC_API_KEY_FILE=/etc/tether/secrets/anthropic.key`를 채우고 `tether-install`을 다시 실행하면 적용됩니다.
- 키를 바꿀 때도 같은 방법을 씁니다.
- 키를 넣지 않은 공급자는 "not configured"로 거부됩니다.

## 7. 정책 바꾸기
설치할 때 기본 정책 하나가 서명되어 들어갑니다. 허용 저장소는 `GITHUB_ORG`의 저장소이고, 인터넷은 github.com, pypi.org, npm만 열립니다. 바꾸려면 다음과 같이 합니다.
```bash
mkdir -p ~/policies && cp /opt/tether/current/policy-default.yaml ~/policies/default.yaml   # 처음 한 번
#   ~/policies/default.yaml을 고칩니다(@GITHUB_ORG@는 실제 조직 이름으로 바꿉니다)
sudo tether-admin policy publish ~/policies /mnt/usb/policy-signing.key
```
- 게시하기 전에 정책 형식을 검사합니다. 틀리면 게시하지 않습니다.
- 키는 네트워크가 없는 컨테이너 안에서만 읽고, 서버에 복사하지 않습니다.
- 끝나면 USB를 뺍니다.

## 8. 설치한 뒤
- **백업:** 매일 03:30에 자동으로 받습니다. 한 달에 한 번 복구 연습을 합니다(`sudo tether-restore --drill <백업>`). 키 묶음은 서버 밖의 다른 매체로 옮겨 두세요. 자세한 내용은 [운영 문서](operations.md) 1–2절에 있습니다.
- **업그레이드:** 새 묶음을 2절처럼 확인한 뒤 `tether-upgrade`로 합니다. [운영 문서](operations.md) 3절을 보세요.
- **서버 재부팅:** Tether와 방화벽이 저절로 다시 뜹니다. `sudo tether-doctor`로 확인합니다.
- **인증서 만료:** 직원 인증서는 90일(재발급), 서버 인증서는 약 1년, CA는 10년입니다. `tether-doctor`가 만료 30일 전부터 경고합니다. 서버 인증서는 `tether-install`을 다시 실행하면 새로 발급됩니다.

## 9. 문제 해결
| 메시지 | 원인과 조치 |
|---|---|
| `release key fingerprint ... is not RELEASE_KEY_SHA256` | 지문을 잘못 옮겼거나 묶음이 바뀌었습니다. 0절의 값과 다시 맞춰 보고, 그래도 다르면 설치하지 말고 연락하세요 |
| `Ubuntu 24.04 required`, `at least 4 CPUs`, `at least 8 GiB memory` | 1절의 서버 조건을 확인합니다 |
| `the kernel has no Landlock LSM` | Ubuntu 24.04 기본 커널을 씁니다. 직접 만든 커널이면 Landlock을 켭니다 |
| `Docker Engine is not installed`, `Docker Engine 28 or later required` | 1절의 "미리 설치할 것"을 확인합니다 |
| `TETHER_ADDRESS ... is not an address of this host` | 서버의 실제 IP를 적습니다(`ip -4 addr`로 확인) |
| `port 443 is in use` | 443을 쓰는 다른 웹 서버를 멈춥니다 |
| `the inference engine ... listens beyond 127.0.0.1` | 엔진이 127.0.0.1에만 열리게 설정합니다(Ollama: `OLLAMA_HOST=127.0.0.1`) |
| `... does not exist (mount the USB stick?)` | USB를 마운트하고 `POLICY_SIGNING_KEY_EXPORT` 경로를 확인합니다 |
| `your SSH address ... is outside ...` | 사무실 대역에서 접속하거나, `ADMIN_NETWORKS`에 지금 접속한 대역을 넣습니다 |
| `Tether ... is installed here; to move to ... use ./install/tether-upgrade` | 다른 버전이 이미 설치돼 있습니다. [운영 문서](operations.md) 3절을 보세요 |
| 설치 직후 SSH가 끊김 | 5분 뒤 방화벽이 저절로 풀립니다. 다시 접속해 `ADMIN_NETWORKS`를 고친 뒤 `tether-install`을 다시 실행합니다 |

해결되지 않으면 `sudo tether-doctor --json`의 결과와 설치 출력을 보내 주세요.

## 이 버전의 제한
- 로그인은 개인 인증서(`mtls`)만 됩니다. 회사 계정(OIDC) 로그인은 다음 버전에서 지원합니다.
- 직원용 도구는 macOS용만 있습니다.
- 에이전트는 `GITHUB_ORG`의 공개 저장소에서만 작업합니다. 비공개 저장소는 GitHub App을 지원한 뒤에 됩니다.
