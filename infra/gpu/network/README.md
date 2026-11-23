# GPU 추론 서버 네트워크 강제 (ADR 0001 D2)

GPU 추론 서버에서 다음 세 가지를 강제하는 설정과 검증 도구입니다. 실제 반영은 인프라팀이 하고, 여기에는 리뷰할 수 있는 설정 파일과 검증 스크립트만 있습니다.

- 서빙 엔진(vLLM/TGI, OpenAI 호환)은 **llm-gateway에서만**, gateway가 가진 클라이언트 인증서로 **mTLS 연결**했을 때만 접근할 수 있습니다. 엔진은 `127.0.0.1`에만 바인딩합니다.
- GPU 서버에는 **일반 egress가 없습니다.** `config.yaml`의 `egress` 목록(DNS, NTP, 패키지 미러, 레지스트리, 로그 전송)만 나갈 수 있습니다.
- SSH는 **bastion을 거쳐 관리자 그룹만** 접속합니다. 세션은 기록하고, agent forwarding과 비밀번호 인증은 막습니다.

## 파일

| 파일 | 내용 |
|---|---|
| `config.yaml` | 기준 설정(single source of truth): 추론 host, 포트, gateway 출발지, bastion, 관리자 그룹, egress 허용 목록 |
| `generate.py` | `config.yaml`을 검증하고 `out/`을 생성합니다. `0.0.0.0/0`, 너무 넓은 대역, http upstream, 도메인 밖 host처럼 잘못된 설정은 거부합니다 |
| `out/nftables/gpu-inference.nft` | 베어메탈용 방화벽입니다. 자체 테이블 `inet gpu_guard`를 쓰고, in/out/forward 모두 기본 drop입니다. drop은 rate limit을 걸어 로그로 남깁니다 |
| `out/envoy/envoy.yaml` | mTLS 종단 프록시입니다. 클라이언트 인증서를 필수로 요구하고, gateway SAN(`llm-gateway.company.internal`)을 고정합니다. 출발지 RBAC를 두고, 허용 경로가 아니면 404를 돌려줍니다. 엔진과 admin은 `127.0.0.1`에만 둡니다 |
| `out/kubernetes/networkpolicy.yaml` | K8s 서빙용입니다. namespace 기본 deny에 gateway → 프록시 포트, 모니터링 → metrics, 파드 → kube-dns만 허용합니다 |
| `out/ssh/gpu-host/` | sshd drop-in, tlog 세션 기록(SSSD), auditd 규칙 |
| `out/ssh/bastion/`, `out/ssh/admin-client/` | bastion sshd drop-in(점프 전용, GPU 서버 22번만 `PermitOpen`), 관리자 `ProxyJump` 설정 |
| `out/gateway.env` | `PLATFORM_LOCAL_INFERENCE_HOSTS`(Policy API), `LOCAL_UPSTREAM`(llm-gateway) 값. `infra/docker-compose.yml`의 변수와 같습니다 |
| `verify.py` | 방화벽 밖에서 실제로 접속해 보는 점검 도구입니다. PASS/FAIL 보고서를 출력하고, 실패가 있으면 exit 1로 끝납니다 |

`out/`은 리뷰용으로 커밋합니다. 테스트가 `out/`과 `config.yaml`을 새로 렌더링한 결과가 다르면 실패하므로, 설정을 바꾸면 `generate.py`를 다시 실행하세요.

```sh
cd infra/gpu/network
uv run -q --no-project --python 3.13 --with pyyaml python generate.py
uv run -q --no-project --python 3.13 --with pytest --with pyyaml pytest -q -p no:warnings tests
```

## 롤아웃 순서

작업 전에 모든 GPU 서버의 **콘솔 접근(IPMI/BMC)** 을 확인합니다. SSH나 방화벽을 잘못 반영해도 복구할 수 있어야 합니다.

1. **설정 확정:** `config.yaml`에 실제 주소를 넣고 `generate.py`를 실행한 뒤 `out/` diff를 리뷰합니다. 서버가 DHCP를 쓰면 egress에 DHCP(udp 67)를 추가합니다.
2. **G-2 먼저 반영:** Policy API에 `PLATFORM_LOCAL_INFERENCE_HOSTS`(`out/gateway.env`)를 설정합니다. 이후 GPU host를 허용하는 샌드박스 정책은 거부됩니다. 기존 트래픽에는 영향이 없습니다.
3. **PKI:**
   - 서버 인증서의 SAN에 upstream 이름(`inference.gpu.company.internal`)을 넣습니다.
   - gateway 클라이언트 인증서는 **gateway 전용 CA**로 발급하고, SAN에 `client_san_dns`를 넣습니다.
   - gateway에는 `LOCAL_CLIENT_CERT`, `LOCAL_CLIENT_KEY`, `LOCAL_CA_BUNDLE`을 비밀값 저장소에서 주입합니다.
4. **프록시와 엔진:**
   - envoy를 `/etc/gpu-inference/envoy.yaml`로 배포하고, 엔진을 `--host 127.0.0.1 --port 8000`으로 재기동합니다.
   - 컨테이너로 돌린다면 host network를 씁니다. forward chain이 drop이라 포트 publish는 동작하지 않습니다.
   - gateway의 `LOCAL_UPSTREAM`을 전환하고 `verify.py --from gateway`를 실행합니다.
5. **SSH:**
   - bastion drop-in을 반영하고 `ssh -J`가 동작하는지 확인합니다.
   - 그다음 GPU 서버에 `10-gpu-inference.conf`, tlog/SSSD, auditd를 반영합니다.
   - 반영 전 `sshd -t`를 실행하고, 기존 세션을 열어 둔 채 새 세션으로 접속을 확인합니다.
6. **nftables(카나리 1대 → 전체):**
   - `nft -c -f gpu-inference.nft`로 문법을 확인합니다.
   - 자동 롤백 타이머를 겁니다: `systemd-run --on-active=10m nft delete table inet gpu_guard`.
   - `nft -f`로 반영한 뒤 두 위치에서 `verify.py`를 실행합니다. 통과하면 타이머를 취소하고 `/etc/nftables.conf`에 include해 영구 반영합니다.
   - drop 로그(`gpu-guard ... drop`)를 하루 이상 보고 누락된 egress가 있는지 확인한 뒤 나머지 서버로 넓힙니다.
7. **K8s 서빙:**
   - Service에 `externalTrafficPolicy: Local`을 설정해 출발지 IP가 보존되는지 먼저 확인합니다.
   - 그다음 `kubectl apply -f out/kubernetes/networkpolicy.yaml`을 실행하고 `verify.py`로 점검합니다.
   - K8s 노드에는 `nftables` 파일을 쓰지 않습니다. CNI 규칙과 충돌하기 때문입니다. 노드 수준 SSH와 egress는 CNI host firewall이나 보안그룹으로 막습니다.

### verify.py 실행

```sh
# (1) 샌드박스·개발자망. --control은 여기서 닿아야 하는 지점(예: bastion SSH)입니다.
#     경로가 아예 없어서 negative 점검이 저절로 통과하는 상황을 걸러 냅니다.
python verify.py --from sandbox --control bastion.company.internal:22 [--cert gw.crt --key gw.key]
# (2) gateway망(gateway egress IP). --other-cert는 같은 CA지만 SAN이 다른 인증서입니다(선택).
python verify.py --from gateway --cert gw.crt --key gw.key --ca ca.pem [--other-cert o.crt --other-key o.key]
```

샌드박스에서 gateway 인증서를 함께 주면, **인증서를 탈취해도 출발지가 다르면 거부되는지**까지 확인합니다.

## 롤백

| 대상 | 방법 |
|---|---|
| nftables | `nft delete table inet gpu_guard`. 자체 테이블만 지우므로 다른 규칙에는 영향이 없습니다. 영구 include도 제거합니다 |
| sshd | drop-in을 삭제하고 `sshd -t && systemctl reload sshd`를 실행합니다. SSH가 끊기면 콘솔로 복구합니다 |
| envoy | 직전 `envoy.yaml`로 되돌립니다. **엔진을 `0.0.0.0`으로 여는 롤백은 하지 않습니다**(G-1 재개방). 장애가 나면 local provider를 끄고 외부 provider로 우회합니다 |
| K8s | `kubectl -n gpu-inference delete networkpolicy llm-inference default-deny-all` |
| tlog/auditd | 설정 파일을 삭제하고 `systemctl restart sssd`, `augenrules --load`를 실행합니다. 롤백하면 감사 공백이 생기므로 보안팀에 통보합니다 |

## 위협 커버리지 (ADR 0001 §5, `docs/threat-model.md`)

| ID | 우회 | 여기서의 통제 |
|---|---|---|
| G-1 | 노트북이나 사내망에서 추론 서버 직접 호출 | 3겹으로 막습니다. ① nftables/NetworkPolicy가 gateway 출발지만 프록시 포트로 받습니다. ② envoy RBAC가 같은 출발지를 다시 확인합니다. ③ mTLS가 gateway CA와 SAN을 고정합니다. 엔진은 loopback에만 있고, 허용하지 않은 경로는 404를 받습니다. `verify.py`의 `*-closed`, `no-cert-refused`, `other-cert-refused`, `stolen-cert-refused` 점검이 이를 확인합니다 |
| G-2 | 샌드박스 정책에 GPU host 추가 | 강제는 Policy API와 컴파일러가 합니다. 여기서는 `generate.py`가 모든 host 이름과 upstream이 `inference.domain` 아래에 있는지 검증해, `PLATFORM_LOCAL_INFERENCE_HOSTS` 하나로 전부 덮이게 합니다 |
| G-7 | GPU 서버 SSH로 서빙 설정 변경 | 다음을 함께 적용합니다. bastion 출발지만 22번 포트로 받고(nftables, sshd `Match Address` 이중 확인), `AllowGroups`로 관리자 그룹만 허용합니다. 공개키만 쓰고 forwarding은 모두 막습니다. bastion은 점프 전용입니다(shell 없음, GPU 서버 22번만 허용). 세션은 tlog로 journald → SIEM에 기록하고, auditd가 `/etc/gpu-inference`, 방화벽, sshd 변경과 모든 execve를 기록합니다 |

D2의 "관리 포트는 관제망에만"은 이렇게 적용합니다. envoy admin은 `127.0.0.1`에 두고, metrics는 모니터링 출발지에서 `GET /metrics`만 허용합니다.

## 설계 결정

- **CiliumNetworkPolicy(FQDN egress)는 만들지 않았습니다.**
  - 서빙 파드에 필요한 egress는 클러스터 DNS뿐입니다. 이미지 pull은 kubelet이 하고, 로그는 노드 에이전트가 보냅니다.
  - host egress는 IP를 고정한 nftables가 맡습니다.
  - FQDN 정책은 DNS 응답을 보고 허용하므로, resolver가 오염되면 함께 뚫립니다. 또 특정 CNI에 묶입니다.
  - 그래서 egress 항목에는 `cidrs`를 필수로 두었습니다. IP가 바뀌는 외부 대상은 사내 미러나 프록시(고정 IP) 뒤에 두세요.
- **envoy를 고른 이유:** SAN 정확 일치(`match_typed_subject_alt_names`), L4 출발지 RBAC, 경로 allow-list를 선언형 설정 하나로 표현할 수 있고, `--mode validate`로 기계적으로 검증할 수 있기 때문입니다.
- **sshd drop-in 이름이 `10-`인 이유:** sshd는 처음 읽은 값을 씁니다. `50-cloud-init.conf`처럼 비밀번호 인증을 다시 켜는 배포판 파일보다 먼저 읽혀야 합니다.
- **업스트림 이름:** `inference.gpu.company.internal`은 DNS round-robin이나 출발지를 보존하는 L4(DSR)로 host에 연결해야 합니다. SNAT하는 LB를 두면 출발지 고정이 깨집니다.
- **tlog 입력 기록:** 입력은 끕니다. 입력을 기록하면 sudo 비밀번호 같은 값도 남기 때문입니다. 명령은 터미널 출력과 auditd execve로 남습니다.

## 검증한 것과 남은 것

로컬에서 검증한 것:
- **pytest:** 생성 규칙과 잘못된 설정 거부, verify 로직(가짜 네트워크)을 확인합니다. 실제 mTLS 서버를 띄워 `Net` 구현도 확인합니다.
- **sshd:** OpenSSH 10.5의 `sshd -T`로 drop-in 문법과 `Match` 동작을 확인했습니다.
- **envoy 1.32와 nftables(Alpine) end-to-end:** Docker 안에서 envoy와 nftables를 띄우고 `verify.py --from gateway/sandbox` 두 경로가 모두 통과하는 것을 확인했습니다. 외부 egress가 차단되는지도 확인했습니다.

아직 확인하지 않은 것:
- 실제 GPU 서버의 배포판 nft/커널 버전, DHCP와 IPv6 환경
- 실제 gateway IP와 PKI
- tlog/SSSD와 auditd의 실제 동작
- K8s NetworkPolicy 적용 결과: CNI가 NetworkPolicy를 지원하는지, 출발지 IP가 보존되는지
- bastion의 MFA
- drop 로그가 SIEM까지 전달되는지
