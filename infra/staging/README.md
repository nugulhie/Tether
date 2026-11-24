# 단일 호스트 staging

GPU 서버 1대에 OpenShell gateway, Tether 컨트롤 플레인, envoy mTLS 프록시를 함께 올려 ADR 0001의 불변식과 G-1·G-2 negative test를 실제 환경에서 검증합니다. 운영 구성(서버 분리)과는 다릅니다.

```
GPU 서버: [Tether 컨트롤 플레인(compose)] + [OpenShell gateway (systemd user)] + [envoy mTLS] → Ollama(127.0.0.1:11434)
Mac:      tether CLI → 오케스트레이터
```

## 순서

| 단계 | 스크립트 | sudo | 하는 일 | 되돌리기 |
|---|---|---|---|---|
| 0 | `00-preflight.sh` | 아니오 | 읽기 전용 점검(OS, cgroups v2, GPU, Ollama 바인딩, 런타임, 포트) | 없음 |
| 1 | `10-docker.sh` | 예 | Docker 공식 apt 저장소(키 지문 확인)에서 Docker Engine 설치, 사용자를 `docker` 그룹에 추가 | 스크립트 상단 주석 |
| 2 | `20-openshell.sh` | 예 | OpenShell v0.1.9 .deb를 SHA-256으로 확인 후 설치, gateway를 사용자 systemd 서비스로 시작(`https://127.0.0.1:17670`), Docker 드라이버 고정, 텔레메트리 끔, linger 켬, CLI에 gateway 등록 | 스크립트 상단 주석 |
| 3 | `30-control-plane.sh` | 아니오 | `infra/.env`에 호스트별 키·토큰 생성(600), compose를 `compose.staging.yml`과 함께 기동(포트는 127.0.0.1만, postgres 비공개), interceptor는 gateway JWT 검증을 켜고 `$XDG_RUNTIME_DIR/tether/` unix 소켓에서 대기 | 스크립트 상단 주석 |
| 4 | `40-gateway-config.sh` | 아니오 | `infra/openshell/gateway.toml`에 staging 소켓 경로를 넣어 `~/.config/openshell/gateway.toml`로 설치, `config preflight` 후 재시작. `binding_policy = "exact"`라 재시작 성공이 곧 바인딩 일치 확인 | 스크립트 상단 주석 |
| 5 | `50-e2e.py` | 아니오 | 실제 gateway에 대고 세션 발급 → 프로바이더 → 샌드박스 생성 → 내부 검사(사용자, 파일시스템, egress, 바이너리 고정) → 정책 확대 시도 → 킬 스위치까지 19개 항목 확인. 종료 코드 = 실패 수 | 스스로 정리 |

`install.sh`를 `main`에서 받아 파이프로 실행하지 않고, 릴리스 .deb를 고정 해시로 설치합니다.

sudo 단계는 서버에서 직접 실행합니다(비밀번호 입력 필요).

```bash
ssh soldoc@192.168.1.27
bash ~/tether-staging/10-docker.sh
exit                                   # docker 그룹 반영을 위해 다시 로그인
ssh soldoc@192.168.1.27
bash ~/tether-staging/20-openshell.sh
bash ~/tether-staging/00-preflight.sh  # Docker, OpenShell이 [ok]인지 확인
# 저장소를 ~/tether에 둔 뒤(sudo 불필요)
cd ~/tether && bash infra/staging/30-control-plane.sh && bash infra/staging/40-gateway-config.sh
python3 infra/staging/50-e2e.py        # SANDBOX_IMAGE(digest 고정)를 infra/.env에 둔 뒤
```

`10-docker.sh` 뒤에 이미 열려 있던 터미널(데스크톱, tmux)에는 docker 그룹이 반영되지 않습니다. 새로 SSH로 접속하거나 `sg docker -c "bash ~/tether-staging/20-openshell.sh"`로 실행합니다. 같은 이유로, 그 전에 시작된 사용자 systemd 관리자 아래의 gateway도 Docker 소켓을 열지 못합니다(`no compute driver configured`). `20-openshell.sh`는 이 경우 gateway만 `sg docker`로 띄우는 drop-in(`~/.config/systemd/user/openshell-gateway.service.d/10-docker-group.conf`)을 둡니다. setuid인 `sg`는 `PrivateTmp`가 만드는 user namespace에서 실패하므로 drop-in에서 `PrivateTmp=false`로 둡니다. 재부팅 뒤에는 필요 없으니 지워도 됩니다.

## 2026-11-24 staging 검증 결과 (OpenShell 0.1.9, Docker 29.10)
- `gateway.toml` preflight 통과, 고의로 깨뜨린 설정은 거부됨
- gateway가 interceptor 바인딩 21개를 `exact`로 수용하고 기동, 프로파일 출처는 `interceptor/tether-governance`뿐
- 실제 gateway에서 거부 확인: 발급되지 않은 샌드박스 생성, 프로파일 import·삭제, 전역 정책 설정, 기본 `github` 프로바이더 생성(프로파일 없음), 발급되지 않은 회사 프로바이더 생성
- `50-e2e.py` 19개 항목 통과(이미지는 `127.0.0.1:5000` 로컬 레지스트리에 올린 local-agent 이미지, digest 고정):
  - 생성: 승인되지 않은 이미지 거부, 프로바이더를 일부만 요청해도 발급 목록 전체로 교체, interceptor가 `tether/session-id`·`tether/policy-hash` 주석을 붙임, 발급되지 않은 프로바이더 attach 거부
  - 샌드박스 내부: uid 10001, `/workspace` 쓰기 가능, `/usr` 쓰기 불가, `/root` 읽기 불가
  - egress: `python3.13`→pypi.org 허용, example.com·api.anthropic.com 차단, 같은 인터프리터를 복사한 바이너리로는 pypi.org도 차단
  - 실행 중 정책 확대 거부, 관리자 세션 철회 → 삭제 → 같은 이름 재생성 거부
- 실제 환경에서 찾아 고친 버그: OpenShell은 샌드박스 이름을 19자(DNS-1123 label, `--` 금지)로 제한한다(`MAX_ROUTABLE_NAME_LEN`). Policy API가 만들던 `agent-<user>-<해시>-<해시>`(최대 59자)는 모든 생성이 `INVALID_ARGUMENT`로 실패했다. 이름을 `a-`(대화형)/`j-`(job) + `sha256(user, repo, static_hash)` 17자로 바꿨다.
- 아직: 샌드박스→LLM gateway 호출(TLS, `host.openshell.internal` 인증서), GitHub App 연동 clone, envoy mTLS→Ollama, 방화벽, GGUF 서명

## 주의
- `docker` 그룹은 root와 같은 권한입니다. staging 전용으로 받아들이고, 운영에서는 gateway 전용 계정을 씁니다.
- Docker는 게시된 컨테이너 포트를 iptables로 직접 열기 때문에 호스트 방화벽(nftables)을 우회할 수 있습니다. 방화벽 단계에서 `DOCKER-USER` 체인과 함께 다룹니다.
- Ollama, GPU 드라이버, SSH 설정은 이 단계에서 건드리지 않습니다.
- 샌드박스에서 본 호스트 주소: OpenShell은 loopback(`127.0.0.0/8`), link-local, unspecified 목적지를 `allowed_ips`로도 허용하지 않습니다. 단일 호스트라도 샌드박스가 부르는 LLM gateway와 Policy API는 `host.openshell.internal`(Docker 드라이버가 샌드박스에 넣어 주는 호스트 별칭) 또는 서버의 LAN IP로 지정하고, 그 이름이 LLM gateway·Policy API TLS 인증서의 SAN에 들어 있어야 합니다. `PLATFORM_LLM_GATEWAY_HOST`, `PLATFORM_POLICY_API_HOST`, 오케스트레이터의 `LLM_GATEWAY_URL`, `POLICY_API_PUBLIC_URL`, 그리고 `openshell/profiles`의 호스트가 같은 이름이어야 합니다. `localhost`/`127.0.0.1`을 쓰면 정책은 로드되어도 연결이 거부됩니다.
- Gateway 설정은 `infra/openshell/gateway.toml`을 기준으로 `~/.config/openshell/gateway.toml`에 두고, 서버에서 `openshell-gateway config preflight --path ~/.config/openshell/gateway.toml`로 검증한 뒤 재시작합니다(로컬 개발 환경에는 `openshell-gateway`가 없어 이 검증은 staging 단계에서만 가능합니다). 같은 호스트의 interceptor는 `INTERCEPTOR_LISTEN=unix:///run/tether/gateway-interceptor.sock`, `GATEWAY_ID=openshell`, `GATEWAY_EXTENSION_PUBLIC_KEY_FILE=~/.local/state/openshell/tls/jwt/public.pem`으로 띄웁니다.
