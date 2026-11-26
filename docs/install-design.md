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
- 사전 조건은 고객사가 갖춘다: Docker Engine 27 이상(고객사 미러에서 설치), GPU 서버라면 NVIDIA 드라이버와 Container Toolkit. 설치 프로그램은 이 조건을 점검만 하고, 직접 설치하지 않는다.

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
