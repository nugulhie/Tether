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
| 2.5 | `60-tls.sh` (**관리자 Mac에서**) | 아니오 | Mac의 `~/.tether-pki`에 CA 2개(서비스용: 이름 제한, 개인용) 생성. 서버에서 키·CSR 생성 → Mac에서 서명 → 인증서만 서버로(`~/.local/state/tether/tls`). 재실행하면 갱신 | `rm -rf ~/.local/state/tether/tls` |
| 2.6 | `infra/pki/tether-pki.sh user <이름>` (**Mac**) | 아니오 | 직원 인증서 발급(90일). 관리자는 서버 `infra/.env`의 `TETHER_ADMIN_USERS`. 퇴사·분실: `tether-pki.sh revoke <이름>` → `60-tls.sh` 재실행 → `docker restart infra-tls-front-1` | `revoke` |
| 3 | `30-control-plane.sh` | 아니오 | `infra/.env`에 호스트별 키·토큰 생성(600), compose를 `compose.staging.yml`과 함께 기동(포트는 127.0.0.1만, postgres 비공개), interceptor는 gateway JWT 검증을 켜고 `$XDG_RUNTIME_DIR/tether/` unix 소켓에서 대기 | 스크립트 상단 주석 |
| 4 | `40-gateway-config.sh` | 아니오 | `infra/openshell/gateway.toml`에 staging 소켓 경로를 넣어 `~/.config/openshell/gateway.toml`로 설치, `config preflight` 후 재시작. `binding_policy = "exact"`라 재시작 성공이 곧 바인딩 일치 확인 | 스크립트 상단 주석 |
| 7 | `70-backup.sh` (**Mac**) | 아니오 | 서버 DB 덤프와 `.env`를 Mac(`~/TetherBackups`)으로 가져오고 감사 해시 체인을 검증, 지난번 head가 그대로인지 비교. 이상하면 macOS 알림. `--install`로 매일 12:30 | `--uninstall` |
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
# (Mac) bash infra/staging/60-tls.sh soldoc@192.168.1.27 192.168.1.27
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
- 아직: GitHub App 연동 clone, orchestrator 컨테이너 경유 실행(OpenShell CLI·인증서 연결), 개인 인증서로 dev 모드 대체, 방화벽, GGUF 서명

## 2026-11-24 모델 호출 경로 (단일 서버)
```
샌드박스(tether-agent) ─TLS─▶ OpenShell 프록시 ─TLS(service CA)─▶ tls-front 127.0.0.1:443 ─┬ /v1/ → Policy API
                                                                                        └ 그 외 → LLM gateway(172.30.0.10)
LLM gateway ─mTLS(llm-gateway.tether.internal)─▶ inference-proxy :8443 (출발지 172.30.0.10만) ─▶ Ollama 127.0.0.1:11434
```
- 인증서: CA 루트 키는 관리자 Mac에만 있다. 서비스 CA는 `host.openshell.internal`, `tether.internal`, 서버 IP, 127.0.0.1로 이름 제한(다른 이름은 `permitted subtree violation`으로 검증 실패 확인). OpenShell은 `gateway.toml`의 `[openshell.supervisor.network] additional_ca_bundle`로 이 CA를 신뢰한다(`40-gateway-config.sh`).
- `host.openshell.internal`은 서버 loopback이다. 그래서 정책 컴파일러는 `network.allow`의 호스트 별칭(`host.openshell.internal`, `localhost` 등), IP 주소, 플랫폼 호스트를 거부한다.
- Ollama 앞 envoy 설정은 `infra/staging/gpu-network.yaml`을 `infra/gpu/network/generate.py`로 렌더링한 것(`out/gpu-network`). DNS가 없어 `gpu-01.gpu.tether.internal`은 LLM gateway 컨테이너의 `extra_hosts`로만 존재한다.
- 확인: 인증서 없이, 다른 출발지에서, 다른 컨테이너에서 inference-proxy 접근 거부. LLM gateway 컨테이너에서만 모델 목록 200.
- `50-e2e.py` 25개 통과(기존 19개 + 6개): python3.13으로 LLM gateway 접근 차단(에이전트 바이너리 아님), 샌드박스에서 호스트 :11434와 서버 IP :8443 차단, `tether-agent`가 qwen3.5:122b 응답 받음(`llm.request local 200`), 프롬프트의 AWS 키는 가드레일이 차단(`guardrail.block`), 정책 밖 모델(bge-m3) 거부(`llm.denied`, 이번에 감사 이벤트 추가). 본문은 암호화 저장 확인.

## 주의
- `docker` 그룹은 root와 같은 권한입니다. staging 전용으로 받아들이고, 운영에서는 gateway 전용 계정을 씁니다.
- Docker는 게시된 컨테이너 포트를 iptables로 직접 열기 때문에 호스트 방화벽(nftables)을 우회할 수 있습니다. 방화벽 단계에서 `DOCKER-USER` 체인과 함께 다룹니다.
- Ollama, GPU 드라이버, SSH 설정은 이 단계에서 건드리지 않습니다.
- 샌드박스에서 본 호스트 주소: OpenShell은 loopback(`127.0.0.0/8`), link-local, unspecified 목적지를 `allowed_ips`로도 허용하지 않습니다. 단일 호스트라도 샌드박스가 부르는 LLM gateway와 Policy API는 `host.openshell.internal`(Docker 드라이버가 샌드박스에 넣어 주는 호스트 별칭) 또는 서버의 LAN IP로 지정하고, 그 이름이 LLM gateway·Policy API TLS 인증서의 SAN에 들어 있어야 합니다. `PLATFORM_LLM_GATEWAY_HOST`, `PLATFORM_POLICY_API_HOST`, 오케스트레이터의 `LLM_GATEWAY_URL`, `POLICY_API_PUBLIC_URL`, 그리고 `openshell/profiles`의 호스트가 같은 이름이어야 합니다. `localhost`/`127.0.0.1`을 쓰면 정책은 로드되어도 연결이 거부됩니다.
- Gateway 설정은 `infra/openshell/gateway.toml`을 기준으로 `~/.config/openshell/gateway.toml`에 두고, 서버에서 `openshell-gateway config preflight --path ~/.config/openshell/gateway.toml`로 검증한 뒤 재시작합니다(로컬 개발 환경에는 `openshell-gateway`가 없어 이 검증은 staging 단계에서만 가능합니다). 같은 호스트의 interceptor는 `INTERCEPTOR_LISTEN=unix:///run/tether/gateway-interceptor.sock`, `GATEWAY_ID=openshell`, `GATEWAY_EXTENSION_PUBLIC_KEY_FILE=~/.local/state/openshell/tls/jwt/public.pem`으로 띄웁니다.

## 2026-11-24 사람 식별(SSO 없음)과 백업
- 직원은 개인 인증서로 식별한다(`AUTH_MODE=mtls`). 직원 Mac → `https://192.168.1.27`(인증서 필수, CRL 확인) → `POST /v1/auth/token`이 1시간 토큰 발급. Policy API는 인증서 이름 헤더를 tls-front 주소(172.30.0.20)에서 온 것만 믿는다. CLI 설정: `TETHER_ORCHESTRATOR=https://192.168.1.27`, `TETHER_CLIENT_CERT`, `TETHER_CLIENT_KEY`, `TETHER_CA_BUNDLE=<service-ca.crt>`; `tether login`은 인증서로 조용히 토큰을 받는다.
- 확인(관리자 Mac에서): 인증서 없음 거부, 다른 사람 인증서로 신원 헤더를 위조해도 실제 인증서 이름으로 덮어씀, 비관리자는 관리 API 403, 서버에서 Policy API 포트로 직접 헤더 위조 403, 샌드박스 리스너의 `/v1/auth/` 404, 폐기한 인증서 `certificate revoked`.
- 관리자 1명: `SINGLE_ADMIN_APPROVAL=1`로 자기 job 승인 허용, 감사 기록에 `self_approved: true`.
- 감사 로그 해시 체인(마이그레이션 0010, `python -m app.audit_chain`, `GET /v1/admin/audit/chain`). 확인: 내용 변조는 체인 검증에서, 해시까지 다시 계산한 변조는 Mac에 저장한 head 비교에서 경보. 백업 덤프를 임시 DB에 복원해 확인.
- e2e 26개 통과(`AUTH_MODE=mtls`, dev 토큰 거부 포함).
