# 설치 프로그램 설계 (ADR 0002, A-1)

결정(2026-11-26):
- 키: 서비스용 CA는 서버에서 생성한다. 정책 서명 키만 서버 밖으로 분리한다.
- 지원 OS: Ubuntu 24.04 LTS만 지원한다.
- 전달 방식: 서명된 오프라인 묶음 파일로 전달한다.

완료 기준: 깨끗한 Ubuntu 24.04 서버에서 우리 엔지니어 없이 하루 안에 설치가 끝나야 한다. CI의 출고 검사에 "깨끗한 VM 설치"를 추가할 수 있어야 한다.

## 1. 묶음 파일 `tether-<버전>.tar`
우리 쪽 CI가 태그(`v*`)마다 만든다. 내용:
```
tether-1.0.0/
  MANIFEST.json        버전, 파일별 sha256, 이미지별 digest, 고정한 외부 구성요소 버전(OpenShell, Claude Code, Codex, Envoy, Postgres)
  MANIFEST.json.sig    MANIFEST.json에 대한 Ed25519 서명(우리 릴리스 키, 오프라인 보관)
  images/*.tar         docker save: 서비스 5개, 샌드박스 2개, postgres, envoy
  debs/openshell_*.deb OpenShell(인터넷 없이 설치)
  install/             설치 프로그램, compose 파일(이미지는 digest로만 지정), systemd 유닛, nftables 규칙, 정책 예시
  release-key.pub      검증용 공개키(설치 안내서에도 지문을 싣는다)
```
- 검증은 `openssl pkeyutl -verify -rawin`(Ubuntu 24.04 기본 OpenSSL 3)으로 한다. 서명을 검증하지 못하면 아무것도 설치하지 않는다.
- 사전 조건은 고객사가 갖춘다: Docker Engine 28 이상(고객사 미러에서 설치), GPU 서버라면 NVIDIA 드라이버와 Container Toolkit. 설치 프로그램은 이 조건을 점검만 하고, 직접 설치하지 않는다.

## 2. 설정 파일 `/etc/tether/tether.conf`
고객사가 채우는 유일한 파일이다. 비밀 값은 넣지 않고 파일 경로만 적는다.
```ini
TETHER_HOSTNAME=tether.corp.example        # 직원 PC와 샌드박스가 부르는 이름(DNS 또는 hosts)
TETHER_ADDRESS=10.0.0.5                    # 직원이 접속하는 주소
AUTH_MODE=oidc                             # oidc(기본) | mtls(IdP가 없는 곳)
OIDC_ISSUER=https://accounts.google.com
OIDC_AUDIENCE=<client id>
OIDC_GROUPS_CLAIM=groups
ADMIN_GROUPS=tether-admins
GITHUB_ORG=corp-example
GITHUB_APP_ID=                             # 비우면 공개 저장소만
LOCAL_INFERENCE_UPSTREAM=                  # 자체 모델 서버(OpenAI 호환), 비우면 외부 모델만
ANTHROPIC_API_KEY_FILE=/etc/tether/secrets/anthropic.key   # 없으면 그 공급자는 "not configured"
OPENAI_API_KEY_FILE=
CONTENT_RETENTION_DAYS=90
```

## 3. 설치 순서 `sudo ./install/tether-install /etc/tether/tether.conf`
각 단계는 다시 실행해도 같은 결과가 나와야 한다. 실패하면 멈추고 그 단계의 되돌리기 방법을 출력한다.
1. **검증:** 묶음 서명과 파일 sha256을 확인한다.
2. **사전 점검:** Ubuntu 24.04, CPU·메모리·디스크, Docker 버전, cgroup v2, Landlock 지원 커널, 포트 443이 비어 있는지, 시간 동기화.
3. **이미지 적재:** `docker load` 후 digest가 MANIFEST와 같은지 확인한다.
4. **비밀 생성:** 서비스 토큰과 내용 암호화 키 묶음(`CONTENT_ENCRYPTION_KEYS_FILE`)을 `/etc/tether/secrets`에 mode 600, root 소유로 만든다. 이미 있으면 덮어쓰지 않는다.
5. **PKI:** 서비스 CA(이름 제약 포함)와 서버 인증서를 `/etc/tether/pki`에 만든다. `AUTH_MODE=mtls`일 때만 직원용 CA도 만든다.
6. **정책 서명 키:** 키 쌍을 만든 뒤 공개키만 서버에 남긴다. 개인키는 관리자가 지정한 경로(USB 등)로 내보내고 서버에서 지운다. 개인키를 내보내기 전에는 설치가 끝나지 않는다.
7. **OpenShell:** 묶음의 .deb를 설치한다. gateway는 시스템 서비스(전용 계정 `tether`, docker 그룹)로 돌리고, interceptor 소켓은 `/run/tether`에 둔다(시범 서버의 사용자 서비스와 linger 방식을 대체한다).
8. **제어부 기동:** 묶음의 compose 파일로 띄운다(`docker compose -p tether`, 이미지는 digest 고정). 마이그레이션은 기동 전에 따로 실행한다(`MIGRATE_ON_STARTUP=0`, 실행 전 백업).
9. **방화벽:** nftables 규칙을 `/etc/nftables.d/tether.nft`로 영구 적용한다. SSH가 끊기면 자동으로 되돌린다(`90-firewall.sh` 방식).
10. **자기 점검:** `tether-doctor`를 실행한다. 모두 통과해야 설치 완료로 본다.

## 4. 자기 점검 `tether-doctor`
설치 직후와 운영 중 언제든 실행한다. 결과는 사람이 읽을 수 있는 출력과 `--json` 두 가지로 낸다.
- 서비스 상태: 각 `/health`, OpenShell gateway, interceptor 소켓
- DB: 마이그레이션 버전이 묶음 버전과 일치하는지, 감사 해시 체인 검증
- 키: 내용 키 묶음 상태(`removable`, `missing`), 정책 서명 공개키 존재, 개인키가 서버에 남아 있지 않은지
- 인증서: 서비스 CA와 서버 인증서 만료일(30일 이내면 경고), CRL 만료
- 공급자: 설정된 모델 공급자, 자체 모델 서버 응답
- 보안 설정: 방화벽 적용, Ollama 등 추론 엔진이 외부에 열려 있지 않은지, `AUTH_MODE=dev`가 아닌지, `SINGLE_ADMIN_APPROVAL`
- 백업: 마지막 백업 시각

## 5. 업그레이드 `sudo ./install/tether-upgrade`
1. 새 묶음을 검증한다.
2. 자동으로 백업한다(DB 덤프, `/etc/tether`). 키 파일은 따로 보관한다.
3. 이미지를 적재한다.
4. 마이그레이션을 실행한다.
5. 재기동한다.
6. `tether-doctor`를 실행한다.

실패하면 이전 이미지와 백업으로 되돌리는 명령을 출력한다. 버전은 건너뛰지 않는다. 지원하는 업그레이드 경로는 MANIFEST에 적는다.

## 6. 시범 서버 스크립트와의 관계
| 지금(`infra/staging/`) | 설치 프로그램 |
|---|---|
| 10-docker, 20-openshell(인터넷에서 받음, 사용자 서비스) | 2·7단계(묶음의 .deb, 시스템 서비스) |
| 30-control-plane(저장소에서 빌드) | 3·4·8단계(묶음의 이미지, digest 고정) |
| 40-gateway-config | 7단계 |
| 60-tls(관리자 Mac에서) | 5단계(서버에서) |
| 80-publish-policies(관리자 Mac 서명) | 6단계 + 관리자 PC의 `tether-policy sign`(개인키는 서버 밖) |
| 90-firewall(재부팅하면 사라짐) | 9단계(영구) |
| 50-e2e | CI 출고 검사의 "깨끗한 VM 설치" 뒤에 실행 |

## 7. 테스트 환경
깨끗한 Ubuntu 24.04 VM 한 대가 필요하다(GPU는 없어도 된다. 외부 모델과 정책·격리 검사는 GPU 없이 가능하다). 출고 검사에서는 이 VM을 매번 초기 상태로 되돌린 뒤 설치 → doctor → e2e를 실행한다.

2026-11-26: 기준 서버에 VM을 만들었다(`infra/testvm/testvm.sh`, 8 vCPU, 16 GB, 60 GB).
- QEMU를 컨테이너 안에서 돌리므로 서버에 패키지를 설치하거나 sudo를 쓰지 않는다.
- VM은 Ubuntu 24.04.5 기본 이미지 그대로다. Docker도 없다. 고객사 서버처럼 사전 조건 설치부터 시험한다.
- 사용법:
  - `bash infra/testvm/testvm.sh reset`: 초기 상태로 되돌린다.
  - `... ssh`: VM에 접속한다.
  - `... down`: VM을 끈다.
- SSH는 서버의 127.0.0.1:2222에만 열린다. 키는 서버의 `~/tether-testvm/id_ed25519`에 있다.
- VM 컨테이너는 전용 Docker 네트워크(`10.250.0.0/24`)에 둔다. VM은 SSH 접속을 이 네트워크의 게이트웨이 주소에서 온 것으로 본다. 그 주소가 `172.17.0.0/16`이면 VM 안에 Docker를 설치하는 순간 VM의 `docker0`가 응답을 가로채 SSH가 끊긴다(실제로 겪었다).
- SSH가 안 될 때는 `testvm.sh console <명령>`을 쓴다. 직렬 콘솔에서 root로 실행된다.
- 처음부터 설치하는 시험은 `bash infra/testvm/install-test.sh <묶음 디렉터리> <버전> <릴리스 키 지문>` 한 번으로 돌린다. VM 초기화 → Docker 설치 → USB 역할의 별도 파일시스템 → 풀기 전 서명 확인 → `tether-install` → 새 SSH 세션에서 방화벽 확인 → `tether-doctor` → e2e(`E2E_NO_LOCAL_MODEL=1`) 순서다.

## 8. 구현 (2026-11-26)
파일은 모두 `infra/installer/`에 있다.
| 파일 | 하는 일 |
|---|---|
| `build-bundle.sh` | 빌드 서버(x86_64, 인터넷)에서 묶음을 만든다. 이미지 11개, OpenShell .deb(SHA-256 고정), 설치 파일, 서명 전 `MANIFEST.json` |
| `sign-bundle.sh` | 릴리스 키가 있는 곳(관리자 Mac, `~/.tether-release`)에서 `MANIFEST.json`과 tar의 sha256에 서명한다. 키는 빌드 서버로 가지 않는다 |
| `tether-install` | 3절의 10단계. 다시 실행해도 같은 결과가 나오고, 실패하면 되돌리는 방법을 출력한다 |
| `tether-doctor` | 4절 점검. 읽기만 한다. `--json`을 지원하고, 종료 코드는 실패 수다 |
| `tether-admin` | `user`·`revoke`(인증서와 CRL 다시 읽기), `policy publish <dir> <USB의 키>`(네트워크 없는 컨테이너에서 서명하고 키는 복사하지 않는다), `compose` |
| `compose.yml`, `tether-openshell-gateway.service`, `firewall.nft`, `policy-default.yaml`, `tether.conf.example` | 설치 대상 파일 |

**설계와 달라진 점**
- **Docker:** 28 이상을 요구한다(OpenShell 요구 사항, 시범 서버 `00-preflight.sh`와 같다).
- **로그인:** 이번 버전은 `AUTH_MODE=mtls`만 설치한다. OIDC는 A-4다.
- **업그레이드:** `tether-upgrade`는 A-2(업그레이드·백업)에서 만든다. 지금 `tether-install`은 마이그레이션 전에 DB를 덤프한다(`/var/lib/tether/backups`).
- **이미지 ID:** 빌드 서버의 로컬 ID가 아니라 저장된 tar의 `index.json` digest를 적는다. Docker containerd 저장소에서는 여러 플랫폼용 이미지의 ID가 index digest라서, `--platform linux/amd64`로 저장해 불러오면 ID가 달라진다.
- **샌드박스 이미지:** 로컬 저장소 컨테이너 `tether-registry`(127.0.0.1:5000)에 올린다. 거기서 받은 digest로 `SANDBOX_IMAGE`와 `ALLOWED_SANDBOX_IMAGES`를 고정한다. compose 이미지는 버전 태그로 부르고, 기동 전에 그 태그가 MANIFEST의 ID인지 확인한다.
- **방화벽:** `/etc/nftables.d`가 아니라 `tether-firewall.service`가 `/etc/tether/firewall.nft`를 부팅 때 적용한다. 적용 후 5분 안에 새 SSH 세션에서 `tether-install confirm-firewall`을 하지 않으면 스스로 풀린다.
- **설정 추가:** `ADMIN_NETWORKS`(SSH와 443을 허용할 대역, 비우면 `TETHER_ADDRESS`의 대역)를 넣었다.
- **묶음 검증:** `tether-install`이 스스로를 검증하는 것만으로는 부족하다(변조된 묶음이면 설치 프로그램 자체도 변조됐을 수 있다). 그래서 tar의 sha256에도 서명해, 고객이 풀기 전에 `openssl`로 확인하게 했다(1절 명령은 `sign-bundle.sh`가 출력한다).
- **정책 서명 키:** 키 쌍은 서버의 tmpfs(`/run`)에서 만들고, 그 키로 첫 정책을 서명한 뒤 개인키를 `POLICY_SIGNING_KEY_EXPORT`로 내보내고 지운다. 내보낸 곳이 서버의 루트 디스크와 같은 장치면 경고한다. `tether-doctor`는 서버 안에서 그 공개키와 짝인 개인키를 찾으면 실패로 본다.

**남은 것**
- OIDC(A-4), `tether-upgrade`와 백업·복구(A-2), 이미지·묶음 서명 자동화와 SBOM(A-7)
- 설치 안내서: 릴리스 키 지문, 사전 조건, `tether.conf` 작성, 첫 관리자 인증서 발급
- 인터넷 없는 상태에서의 설치 확인. 시험 VM은 인터넷이 된다. 묶음에 OpenShell 감독 이미지를 넣었지만, gateway가 그 이미지를 새로 받으려 하지 않는지는 아직 막힌 네트워크에서 확인하지 않았다.
- 자체 모델이 있는 설치(`LOCAL_INFERENCE_PORT`)는 VM에 GPU가 없어 확인하지 않았다.
