# Broken Access Control Lab

PoC scanner의 `broken_access_control` 엔드포인트 PoC를 검증하기 위한 독립 테스트 서버입니다.

이 lab은 일부러 취약한 `/vuln/*` 엔드포인트와 올바르게 차단하는 `/safe/*` 엔드포인트를 같이 제공합니다. scanner가 양성 케이스는 잡고, 음성 케이스는 취약으로 표시하지 않는지 확인할 수 있습니다.

## Run

Docker로 실행:

```bash
cd /Users/jangeuna/main/labs/broken-access-control
docker compose up --build
```

Python으로 바로 실행:

```bash
cd /Users/jangeuna/main/labs/broken-access-control
PORT=9001 python3 app/server.py
```

실행 후 로컬 브라우저나 터미널에서는 `http://127.0.0.1:9001`로 접근합니다. scanner backend가 `scanner-lab-net` Docker 네트워크에 연결되어 있으면 scanner의 `base_url`은 `http://broken-access-control-lab:9000`을 사용합니다.

## Sessions

테스트용 로그인 값:

```text
Cookie: session=kim
Cookie: session=lee
Cookie: session=admin
Authorization: Bearer kim-token
Authorization: Bearer lee-token
Authorization: Bearer admin-token
```

브라우저/터미널에서 쿠키 발급:

```bash
curl -i "http://127.0.0.1:9001/login?user=kim"
```

## Endpoints

취약 케이스:

```text
GET    /vuln/profile?user_id=1
POST   /vuln/document        {"document_id": 1001}
DELETE /vuln/post?post_id=1
GET    /vuln/private-dashboard
GET    /vuln/admin/users
```

정상 차단 케이스:

```text
GET    /safe/profile?user_id=1
POST   /safe/document        {"document_id": 1001}
DELETE /safe/post?post_id=1
GET    /safe/private-dashboard
GET    /safe/admin/users
```

전체 카탈로그 확인:

```bash
curl "http://127.0.0.1:9001/catalog"
```

## Scanner Payloads

scanner backend가 Docker로 실행 중일 때:

```bash
curl -sS -X POST "http://127.0.0.1:8001/api/v1/endpoints/scans" \
  -H "Content-Type: application/json" \
  --data-binary @examples/scanner-vulnerable.json
```

음성 케이스:

```bash
curl -sS -X POST "http://127.0.0.1:8001/api/v1/endpoints/scans" \
  -H "Content-Type: application/json" \
  --data-binary @examples/scanner-safe.json
```

scanner backend를 Docker 밖에서 실행한다면 예시 JSON의 `base_url`을 `http://127.0.0.1:9001`로 바꿔 사용하면 됩니다.
