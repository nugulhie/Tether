# GPU 가중치·이미지 서명 (ADR 0001 G-6)

GPU 추론 서버는 회사가 서명한 가중치와 서빙 이미지만 실행합니다. 검증은 fail-closed입니다. 키를 모르거나, 파일이 더 있거나 빠졌거나, symlink가 있거나, cosign이 없으면 엔진은 시작하지 않습니다. 검증을 건너뛰는 플래그나 환경변수는 일부러 두지 않았습니다.

| 파일 | 내용 |
|---|---|
| `modelsign.py` | `keygen`, `manifest`, `sign`, `verify`(가중치), `verify-image`(cosign). 의존성은 `cryptography`와 표준 라이브러리 |
| `systemd/gpu-inference.service.d/10-verify-signatures.conf` | 베어메탈용 drop-in. `ExecStartPre=`로 이미지와 가중치를 검증한 뒤에만 엔진 시작 |
| `systemd/serving.env.example` | 이미지 digest, 모델 이름·버전·경로. 엔진의 `ExecStart`도 같은 값을 씀 |
| `k8s/cluster-image-policy.yaml` | Sigstore policy-controller. `gpu-inference` 네임스페이스의 모든 이미지에 회사 서명 요구 |
| `k8s/require-digest.yaml` | ValidatingAdmissionPolicy. 태그 대신 digest만 허용 |
| `k8s/inference-weights-verify.example.yaml` | init container로 가중치를 검증한 뒤 vLLM을 시작하는 예시 |

테스트: `cd infra/gpu/signing && uv run -q --no-project --python 3.13 --with pytest --with cryptography pytest -q -p no:warnings tests`

## 동작

**가중치.** `manifest`는 디렉터리를 훑어 파일마다 경로·크기·sha256을 경로순으로 기록합니다. symlink, 특수 파일, pickle이 들어갈 수 있는 형식(`.bin .pt .pth .pkl .pickle .ckpt .joblib`)이 있으면 거부합니다. safetensors만 허용한다는 ADR의 결정을 따른 것입니다. `sign`은 정책 번들과 같은 방식으로 서명합니다. canonical JSON에 Ed25519로 서명하고, `key_id`가 붙은 detached 서명(`model-manifest.json.sig`)을 만듭니다. `verify`는 아래 순서로 확인하고, 하나라도 어긋나면 non-zero로 끝납니다.

1. 신뢰 키 저장소를 읽습니다(`<key_id>.pub`). 저장소가 group/others 쓰기 가능하면 실패합니다. 읽기 전용 마운트는 예외입니다.
2. 서명 봉투의 `key_id`가 저장소에 있는지 봅니다(`unknown_key`). 다음으로 manifest digest가 서명 시점과 같은지(`manifest_modified`), 서명이 맞는지(`bad_signature`) 확인합니다.
3. `--expect-model`과 `--expect-version`이 manifest와 같은지 봅니다. 예전에 정상 서명된 버전으로 바꿔치기하는 롤백을 막습니다.
4. 디스크를 다시 훑습니다(`symlink`, `missing_file`, `extra_file`, `size_mismatch`). 그다음 모든 파일을 8 MiB 단위 스트리밍으로 다시 해시합니다(`hash_mismatch`). 파일은 `O_NOFOLLOW`로 엽니다.

성공하든 실패하든 stdout에는 JSON 한 줄만 나옵니다.
`{"event":"model.verify","model":…,"version":…,"manifest_sha256":…,"key_id":…,"result":"success|failure","reason":…,"detail":…,"host":…,"ts":…}`
`verify-image`는 같은 형식의 `image.verify`(`image`, `digest`, `key_id`)를 냅니다. Policy API 연동은 이 이벤트를 받아서 붙입니다.

**이미지.** `verify-image`는 `registry/repo@sha256:<digest>` 형식만 받습니다. 태그와 `tag@digest`는 cosign을 부르기 전에 거부합니다. 그다음 신뢰 키마다 `cosign verify --key <key> --insecure-ignore-tlog=true <image>`를 실행하고, 하나라도 통과하면 성공입니다. 키를 여러 개 두는 것은 교체 기간을 위해서입니다.

**keyless가 아니라 키 기반인 이유.** keyless는 Fulcio 인증서와 공개 Rekor 투명성 로그 조회가 필요합니다. GPU 서버는 G-1에 따라 출발지와 목적지가 닫혀 있어서 외부 Sigstore에 닿지 않습니다. 이미지 저장소도 사내에 있습니다. 키 기반이면 신뢰 기준이 고정한 공개키 하나로 끝나고, 오프라인에서 검증되며, 가중치 서명과 같은 키 운영 절차를 씁니다. `--insecure-ignore-tlog`는 공개 로그 조회를 끄는 옵션일 뿐입니다. 서명과 digest claim은 계속 검증합니다. 나중에 사내 Rekor를 두면 이 옵션을 빼면 됩니다.

**Kubernetes에서 policy-controller를 고른 이유.** Kyverno보다 policy-controller를 골랐습니다. 하는 일이 서명 검증 하나라서 범위가 좁고, cosign과 같은 검증 코드를 씁니다. 범용 정책 엔진을 새로 운영할 필요도 없습니다. digest 강제는 별도 플러그인 없이 쿠버네티스 내장 CEL 정책(`require-digest.yaml`)으로 처리합니다. 설치할 때 `no-match-policy=deny`와 webhook `failurePolicy: Fail`을 설정합니다. 둘 다 빠지면 fail-open입니다.

## 키 세레모니와 교체

- **키는 두 벌입니다.** 가중치용 `model-<연도><순번>`(Ed25519, modelsign)과 이미지용 `image-<연도><순번>`(cosign)입니다. 용도를 섞지 않습니다. 이미지 키로 서명한 다른 사내 이미지가 서빙 이미지로 통과하면 안 되기 때문입니다.
- **생성.** 오프라인 서명 호스트에서 관리자 2인이 입회합니다. `modelsign.py keygen`은 0600 파일로 만듭니다. 보관용으로는 암호화 PEM으로 바꿔 사내 비밀 저장소에 넣고(`sign --key-password-env`로 사용), cosign 키는 KMS URI(`cosign generate-key-pair --kms …`)를 권장합니다. 개인키는 저장소, 로그, CI 변수 평문에 두지 않습니다. `sign`은 키 파일 권한이 0600이 아니면 거부하고, 오류 메시지에도 키 내용을 넣지 않습니다.
- **서명.** 모델 반입 요청을 검토한 뒤 서명 호스트에서 `manifest`, 사람 검토, `sign` 순으로 진행합니다. 이미지는 CI가 digest로 빌드하고, 서명은 승인을 거친 job만 합니다.
- **정기 교체(연 1회).** 새 공개키를 추가해 배포하고, 현재 모델과 이미지를 새 키로 다시 서명합니다. 그다음 옛 공개키를 지웁니다. 키 파일이 없으면 그 키는 신뢰하지 않습니다.
- **유출 시.** 해당 공개키를 즉시 지워 배포하고, 새 키로 다시 서명합니다. 다시 서명하기 전까지는 재시작하는 서버가 올라오지 않는데, 의도한 동작입니다. 이미 떠 있는 프로세스는 계속 돕니다. 필요하면 재시작해서 강제로 재검증합니다.

## 공개키 위치

- 원본: 이 저장소 `infra/gpu/signing/keys/model/<key_id>.pub`, `keys/image/<key_id>.pub`(공개키만, 보안팀 CODEOWNERS 리뷰). 첫 세레모니 때 만듭니다.
- 베어메탈: 설정관리 도구가 `/etc/company/signing/model-keys/`와 `/etc/company/signing/image-keys/`(root:root, 디렉터리 0755, 파일 0644)에 배포합니다. 서빙 사용자가 쓸 수 있으면 `verify`가 실패합니다.
- 쿠버네티스: 가중치 키는 ConfigMap(`model-signing-keys`, 읽기 전용 마운트)에 둡니다. 이미지 키는 `ClusterImagePolicy`의 `authorities`에 넣습니다.

## 롤아웃

1. Staging GPU 노드 1대에서 시작합니다. 현재 모델과 이미지를 서명하고 drop-in을 설치한 뒤 재시작해 `model.verify` 성공 이벤트를 확인합니다. negative test도 돌립니다. 가중치 1바이트 변조, 파일 추가, 태그 이미지, 서명 안 된 이미지가 모두 막혀야 합니다.
2. 쿠버네티스는 staging에서만 잠깐 `mode: warn`으로 기존 워크로드를 확인한 뒤 `enforce`로 바꿉니다. 운영에는 처음부터 `enforce`로 들어갑니다.
3. 운영 노드에 순차 적용합니다. SIEM에 두 가지 규칙을 둡니다. 하나는 `result=failure` 경보입니다. 다른 하나는 엔진이 시작했는데 직전에 `model.verify` 성공 이벤트가 없는 경우입니다. drop-in을 지운 상황(G-7)을 잡기 위한 규칙입니다.
4. 엔진 쪽 고정 설정: 이미지는 `${SERVING_IMAGE}` digest로 실행하고, 가중치는 읽기 전용으로 마운트합니다. `--load-format safetensors`를 쓰고 `--trust-remote-code`는 쓰지 않습니다.

## break-glass

- 가드레일 break-glass(`/v1/admin/guardrails/bypass`)는 가드레일만 해제합니다. 서명 검증과는 아무 관계가 없습니다. modelsign에는 우회 플래그, 환경변수, Policy API 조회가 없습니다. 그래서 가드레일 해제 상태에서도 서명이 안 된 가중치나 이미지는 뜨지 않습니다.
- 긴급 상황에서도 검증을 끄지 않습니다. 대신 둘 중 하나를 합니다.
  1. 직전에 서명된 버전으로 `serving.env`를 되돌립니다.
  2. 세레모니 절차를 줄여 2인 입회로 급히 서명합니다.
- drop-in 제거나 `serving.env` 수동 편집은 GPU 서버 root 권한이 필요합니다. 이 경로는 G-7 통제(bastion, 관리자, 감사)와 위 SIEM 규칙으로 잡습니다.

## 남은 한계

- 검증과 로드 사이에 시간 차(TOCTOU)가 있습니다. 가중치 디렉터리를 root 소유 읽기 전용으로 두고 컨테이너에 `:ro`로 마운트하는 것이 전제입니다.
- GPU 서버의 root는 drop-in, 키 저장소, 엔진 설정을 모두 바꿀 수 있습니다. 이 위협은 탐지(감사, SIEM)로 대응합니다.
- 서명은 "회사가 승인했다"는 뜻이지 "모델이 안전하다"는 뜻이 아닙니다. 반입 검토는 서명 전에 사람이 합니다.
