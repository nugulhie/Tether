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
| 2 | `20-openshell.sh` | 예 | OpenShell v0.1.9 .deb를 SHA-256으로 확인 후 설치, gateway를 사용자 systemd 서비스로 시작(`https://127.0.0.1:17670`), 텔레메트리 끔, linger 켬 | 스크립트 상단 주석 |

`install.sh`를 `main`에서 받아 파이프로 실행하지 않고, 릴리스 .deb를 고정 해시로 설치합니다.

sudo 단계는 서버에서 직접 실행합니다(비밀번호 입력 필요).

```bash
ssh soldoc@192.168.1.27
bash ~/tether-staging/10-docker.sh
exit                                   # docker 그룹 반영을 위해 다시 로그인
ssh soldoc@192.168.1.27
bash ~/tether-staging/20-openshell.sh
bash ~/tether-staging/00-preflight.sh  # Docker, OpenShell이 [ok]인지 확인
```

## 주의
- `docker` 그룹은 root와 같은 권한입니다. staging 전용으로 받아들이고, 운영에서는 gateway 전용 계정을 씁니다.
- Docker는 게시된 컨테이너 포트를 iptables로 직접 열기 때문에 호스트 방화벽(nftables)을 우회할 수 있습니다. 방화벽 단계에서 `DOCKER-USER` 체인과 함께 다룹니다.
- Ollama, GPU 드라이버, SSH 설정은 이 단계에서 건드리지 않습니다.
- 샌드박스에서 본 호스트 주소: OpenShell은 loopback(`127.0.0.0/8`), link-local, unspecified 목적지를 `allowed_ips`로도 허용하지 않습니다. 단일 호스트라도 샌드박스가 부르는 LLM gateway와 Policy API는 `host.openshell.internal`(Docker 드라이버가 샌드박스에 넣어 주는 호스트 별칭) 또는 서버의 LAN IP로 지정하고, 그 이름이 LLM gateway·Policy API TLS 인증서의 SAN에 들어 있어야 합니다. `PLATFORM_LLM_GATEWAY_HOST`, `PLATFORM_POLICY_API_HOST`, 오케스트레이터의 `LLM_GATEWAY_URL`, `POLICY_API_PUBLIC_URL`, 그리고 `openshell/profiles`의 호스트가 같은 이름이어야 합니다. `localhost`/`127.0.0.1`을 쓰면 정책은 로드되어도 연결이 거부됩니다.
- Gateway 설정은 `infra/openshell/gateway.toml`을 기준으로 `~/.config/openshell/gateway.toml`에 두고, 서버에서 `openshell-gateway config preflight --path ~/.config/openshell/gateway.toml`로 검증한 뒤 재시작합니다(로컬 개발 환경에는 `openshell-gateway`가 없어 이 검증은 staging 단계에서만 가능합니다). 같은 호스트의 interceptor는 `INTERCEPTOR_LISTEN=unix:///run/tether/gateway-interceptor.sock`, `GATEWAY_ID=openshell`, `GATEWAY_EXTENSION_PUBLIC_KEY_FILE=~/.local/state/openshell/tls/jwt/public.pem`으로 띄웁니다.
