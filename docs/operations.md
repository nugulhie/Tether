# 운영: 백업, 복구, 업그레이드 (ADR 0002, A-2)

설치 프로그램(`tether-install`)으로 설치한 서버의 운영 절차입니다. 명령은 모두 서버에서 root(`sudo`)로 실행합니다. 설치 자체는 [설치 프로그램 설계](install-design.md)를 보세요.

## 1. 백업 `tether-backup`
설치하면 매일 03:30(최대 15분 지연)에 `tether-backup.timer`가 백업합니다. 서버가 꺼져 있어 놓친 백업은 켜진 뒤에 실행됩니다. 직접 실행할 수도 있습니다.
```bash
sudo tether-backup                          # 지금 백업
sudo tether-backup --label before-change    # 이름 붙인 백업: 자동으로 지우지 않음
sudo tether-backup --keys-out /mnt/usb      # 키 묶음은 USB 등 다른 매체에 쓰기
```
백업 하나는 `/var/lib/tether/backups/<UTC 시각>-<버전>[-<이름>]/` 디렉터리 하나입니다(root만 읽기).
| 파일 | 내용 |
|---|---|
| `db.dump` | Postgres 전체(`pg_dump -Fc`): 정책, 세션, 작업, 감사 기록, 암호화된 프롬프트·응답 |
| `broker.db` | 자격 증명 브로커 저장소(SQLite 온라인 백업). 안의 비밀은 암호화되어 있음 |
| `config.tar.gz` | `/etc/tether`와 OpenShell CLI 설정 중 비밀이 아닌 것: 설정, 인증서, 정책 공개키, 디렉터리 권한 |
| `keys.tar.gz` | 비밀 전부: `secrets.env`, `compose.env`, 두 CA의 개인키, 서버 개인키, OpenShell 게이트웨이 키와 상태 |
| `backup.json` | 버전, 마이그레이션 번호, 감사 체인 머리, 각 파일의 SHA-256 |

- **키와 데이터는 따로 보관합니다.** `db.dump`만으로는 내용을 읽을 수 없고 `keys.tar.gz`가 있어야 합니다. 서버 밖으로 복사할 때 두 가지를 다른 매체나 금고에 둡니다.
- **이름 없는 백업은 최근 14개만 남깁니다**(`--keep N`). 이름 붙은 백업(`pre-upgrade-…`, `pre-restore`)은 직접 지울 때까지 남습니다.
- **감사 기록 변조를 확인합니다.** 백업할 때마다 감사 해시 체인을 검증합니다. 또 지난 백업(또는 복구) 때 기록한 체인 머리가 지금도 같은 해시인지 봅니다. 다르면 백업은 남기되 종료 코드 3과 `ALERT`를 냅니다. 체인 전체를 다시 계산해 바꾼 경우는 서버 안에서는 알 수 없으므로, `backup.json`의 `audit.head_hash`를 서버 밖에 남겨 두세요.
- **정책 서명 개인키는 백업에 없습니다.** 처음부터 서버에 없기 때문입니다. 설치할 때 내보낸 USB를 따로 보관합니다.

## 2. 복구 연습 `tether-restore --drill`
한 달에 한 번 합니다. `tether-doctor`는 35일이 지나면 경고합니다. 설치에는 아무것도 바꾸지 않습니다.
```bash
sudo tether-restore --drill /var/lib/tether/backups/<백업>
sudo tether-restore --drill <백업> --keys /mnt/usb/<백업>-keys.tar.gz   # 키를 따로 둔 경우
```
확인하는 것:
- 각 파일이 `backup.json`의 해시와 같은지
- DB를 임시 DB에 복원했을 때 마이그레이션 번호가 맞는지
- 감사 체인이 검증되고 그 머리가 `backup.json`과 같은지
- **백업의 키로** 저장된 모든 내용이 열리는지
- 브로커 저장소의 무결성
- 키 묶음에 두 CA가 있는지

임시 DB는 끝나면 지웁니다.

## 3. 업그레이드 `tether-upgrade`
새 버전 묶음을 받으면 먼저 풀기 전에 서명을 확인합니다(설치 안내서의 명령). 그다음 **새 묶음의** `tether-upgrade`를 실행합니다.
```bash
sudo ./tether-<새 버전>/install/tether-upgrade /etc/tether/tether.conf
```
1. 묶음을 검증합니다. 새 묶음의 `MANIFEST.json` `upgrade_from`에 지금 버전이 없으면 거부합니다. 버전은 건너뛰지 않고 낮추지도 않습니다.
2. 전체 백업을 받습니다(`<시각>-<지금 버전>-pre-upgrade-to-<새 버전>`). 실패하면 아무것도 바꾸지 않고 멈춥니다.
3. 설치 단계를 그대로 실행합니다: 이미지, 인증서, DB 마이그레이션(앞으로만), 재기동, 방화벽.
4. `tether-doctor`를 실행합니다.

백업 뒤 어느 단계에서든 실패하면 되돌리는 명령을 출력합니다(4절). 백업과 되돌리기 사이에 쓰인 데이터(새 감사 기록, 작업)는 되돌리면 사라집니다. 그러니 업무 시간 밖에 하세요. 업그레이드해도 감사 해시 체인은 이어집니다. 마이그레이션은 행을 지우거나 다시 쓰지 않습니다.

이전 버전의 파일(`/opt/tether/<버전>`)과 이미지는 지우지 않습니다. 되돌리기에 필요하기 때문입니다.

## 4. 되돌리기와 복구 `tether-restore`
**같은 서버를 백업 시점으로**(업그레이드 실패 후 되돌리기 포함):
```bash
sudo tether-restore /var/lib/tether/backups/<백업>
```
1. 지금 상태를 먼저 `pre-restore` 백업으로 남깁니다(`--no-safety-backup`으로 생략).
2. Tether를 멈춥니다.
3. 설정, 키, OpenShell 게이트웨이 상태를 백업 것으로 바꿉니다. 바뀌기 전 파일은 `/var/lib/tether/restore-<시각>/`에 남습니다.
4. 백업을 받았던 버전(`/opt/tether/<버전>`)으로 전환합니다.
5. DB와 브로커 저장소를 복원합니다.
6. 기동하고 `tether-doctor`를 실행합니다.

**새 서버로(서버를 잃은 경우)**:
```bash
sudo ./install/tether-restore --config-only <백업>     # 1. 설정과 키(설치 전). 주소가 바뀌었으면 /etc/tether/tether.conf 수정
sudo ./install/tether-install /etc/tether/tether.conf  # 2. 백업과 같은 버전의 묶음. 키는 그대로 쓰고, 주소가 바뀌었으면 서버 인증서만 새로 발급
sudo tether-restore --data-only <백업>                 # 3. DB와 브로커 저장소
```
- 사용자 인증서는 그대로 씁니다. 사용자 CA가 백업에 있기 때문입니다.
- OpenShell 버전이 백업과 다르면 경고합니다. 그 버전 묶음의 `.deb`로 맞춥니다.

## 5. 점검
`tether-doctor`의 `backup` 항목은 다음을 봅니다.
- 마지막 백업이 2일 안인지
- `tether-backup.timer`가 켜져 있는지
- 35일 안에 복구 연습을 했는지

## 6. 출고 전 시험
`infra/testvm/upgrade-test.sh`는 깨끗한 VM에서 다음을 한 번에 시험합니다([릴리스 기준](release.md) 3절).
1. 이전 버전을 설치하고 사용합니다.
2. 새 버전 `tether-install`이 이전 버전을 덮어쓰지 못하는지 확인합니다.
3. 업그레이드한 뒤 doctor와 e2e를 돌립니다.
4. 백업과 복구 연습을 합니다.
5. 업그레이드 전 백업으로 되돌린 뒤, 업그레이드 전 마지막 감사 이벤트의 해시가 같은지 확인하고 doctor와 e2e를 돌립니다.
6. 다시 업그레이드합니다.

## 아직 없는 것
- 마이그레이션이 있는 업그레이드의 실제 시험: 지금 출고된 버전들은 마이그레이션 번호가 같다(0013). 다음에 마이그레이션이 추가되는 버전에서 같은 시험으로 확인한다.
- 새 서버 복구(`--config-only` → 설치 → `--data-only`)의 VM 시험
- 서버 밖 백업 복사 자동화(지정한 NFS·S3로 내보내기), 백업 파일 자체의 암호화(키 묶음을 관리자 공개키로 암호화)
- 정책 서명 키 분실 시 교체 절차(새 키 쌍으로 다시 서명, 공개키 교체)
