# 릴리스 기준 (ADR 0002, A-6)

한 버전을 고객에게 내보내려면 아래 기준을 모두 통과해야 합니다. 하나라도 빨간불이면 출고하지 않습니다.

## 1. CI (자동, PR과 main마다)
| 검사 | 워크플로 | 무엇을 막는가 |
|---|---|---|
| `test` | `test.yml` | 단위·통합 테스트 727개(`make test`) |
| `schema` | `release-gate.yml` | 실제 Postgres에서 마이그레이션 결과가 모델과 다름, 되돌리기 실패(`python -m app.schema_check`) |
| `images` | `release-gate.yml` | 샌드박스 이미지(local-agent, coding-agents)와 interceptor 이미지 빌드 실패 |
| `smoke` | `release-gate.yml` | 빌드한 이미지끼리 실제로 못 붙음: 기동, Postgres 마이그레이션, 세션 발급, 게이트웨이↔Policy API 인증, 감사 기록과 해시 체인(`make smoke`) |

GitHub 설정에서 main의 필수 검사(required status checks)로 `test`, `schema`, `images`, `smoke`를 지정합니다.

## 2. 기준 서버 e2e (사람, 출고 전 한 번)
CI에는 OpenShell, GPU가 없으므로 샌드박스 격리는 기준 서버에서 확인합니다.
```bash
# 기준 서버(지금은 192.168.1.27)에 출고할 커밋을 올리고
bash infra/staging/30-control-plane.sh
python3 infra/staging/50-e2e.py      # "0 failed"여야 함
```
확인하는 것: 승인되지 않은 이미지 거부, 샌드박스 권한·파일·네트워크 제한, 정책 확대 거부, 긴급 차단, 로컬 모델 작업 실행과 결과, Claude Code·Codex의 게이트웨이 경유(회사 키가 있으면 실제 응답까지).

## 3. 버전과 기록
- 태그 `vX.Y.Z`. 태그 push에도 `release-gate`가 다시 돕니다.
- 릴리스 노트: DB 마이그레이션 번호, 설정 변경(새 환경변수), 이미지 digest, 고정한 에이전트 버전(Claude Code, Codex), 알려진 제한.
- 업그레이드 전 백업은 필수입니다(마이그레이션은 앞으로만 자동, 되돌리기는 백업 복구가 기본).

## 아직 기준에 없는 것 (로드맵 A-1, A-7)
- 깨끗한 VM에 설치 프로그램으로 처음부터 설치하는 검사([설치 프로그램 설계](install-design.md) 7절, 설치 프로그램이 생기면 추가)
- 이미지 서명과 SBOM, 서비스 이미지의 베이스 digest 고정과 의존성 고정(지금 `services/*/Dockerfile`은 `python:3.13-slim`과 범위 지정 의존성)
- 이전 버전 DB에서 새 버전으로의 업그레이드 검사(첫 출고 버전이 생기면 그 DB 덤프로)
