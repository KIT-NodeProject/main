# CVE Backend PoC

`CVE Backend PoC`는 스캔 대상 정보를 저장하고, 수동으로 입력한 기술 스택과 버전을 기준으로 시드된 CVE 카탈로그와 매칭한 뒤, 결과를 저장하는 간단한 FastAPI 백엔드 프로토타입입니다.

이 저장소의 목적은 CVE 매핑을 위한 백엔드 흐름과 데이터 모델링을 검증하는 것이며, 운영 환경에서 바로 사용할 수 있는 상용 수준의 취약점 스캐너를 목표로 하지는 않습니다.

이 문서의 명령은 `backend/` 디렉터리에서 실행하는 것을 기준으로 합니다. 저장소 루트에서 시작했다면 먼저 `cd backend` 후 진행하면 됩니다.

## 빠른 시작

처음 실행해보는 경우에는 아래 순서만 따라가면 됩니다.

```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
docker compose up -d
cp .env.example .env
alembic upgrade head
python -m app.seeds.load_cve_seed
uvicorn app.main:app --reload
```

정상적으로 실행되면 아래 주소에서 바로 확인할 수 있습니다.

- API 상태 확인: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`

## 프로젝트 범위

- `base_url`과 기술 스택 정보를 포함한 스캔 대상 생성
- 특정 대상에 대한 CVE 매칭 스캔 실행
- 스캔 결과 저장 및 조회
- PostgreSQL에 예시 CVE 데이터 적재

현재 한계:

- 프로토타입 / PoC 단계
- 기술 스택 식별 방식은 `manual_input`만 지원
- CVE 데이터는 외부 실시간 피드가 아니라 로컬 시드 파일 기반
- 매칭은 저장된 제품명과 버전 범위 비교 로직 기반
- 인증, 권한 관리, 백그라운드 작업, 운영 환경 대응 미구현

## 기술 스택

- Python 3.11
- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL 16
- Pydantic

## 시작 전에 확인할 것

- Docker가 실행 중이어야 합니다.
- Python 3.11이 설치되어 있어야 합니다.
- 기본 포트는 PostgreSQL `5432`, API 서버 `8000`을 사용합니다.

## 동작 흐름

1. `base_url`과 `tech_stack` 정보를 포함해 대상 생성
2. 생성된 대상에 대해 스캔 실행
3. 저장된 스캔 결과 조회

주요 API:

- `GET /health`
- `POST /targets`
- `POST /targets/{target_id}/scan`
- `GET /targets/{target_id}/results`

## 로컬 실행 방법

### 1. PostgreSQL 실행

```bash
docker compose up -d
```

### 2. `.env` 파일 생성

`backend/` 디렉터리에 `.env` 파일을 생성합니다.

```env
DATABASE_URL=postgresql+psycopg://cve_user:cve_password@localhost:5432/cve_db
```

또는 예시 파일을 그대로 복사해도 됩니다.

```bash
cp .env.example .env
```

### 3. 의존성 설치

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 4. 데이터베이스 마이그레이션 적용

```bash
alembic upgrade head
```

### 5. 예시 CVE 데이터 적재

```bash
python -m app.seeds.load_cve_seed
```

### 6. API 서버 실행

```bash
uvicorn app.main:app --reload
```

서버는 `http://127.0.0.1:8000`에서 확인할 수 있습니다.

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## 사용 예시

### 헬스 체크

```bash
curl http://127.0.0.1:8000/health
```

### 대상 생성

```bash
curl -X POST http://127.0.0.1:8000/targets \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "https://example.com",
    "tech_stack": {
      "stack_name": "nginx",
      "version": "1.18.0"
    }
  }'
```

응답 예시:

```json
{
  "target_id": 1,
  "base_url": "https://example.com/",
  "status": "pending",
  "created_at": "2026-03-21T00:00:00Z",
  "tech_stack": {
    "stack_id": 1,
    "target_id": 1,
    "stack_name": "nginx",
    "version": "1.18.0",
    "identify_method": "manual_input"
  }
}
```

### 스캔 실행

```bash
curl -X POST http://127.0.0.1:8000/targets/1/scan
```

응답 예시:

```json
{
  "message": "Scan completed",
  "target_id": 1,
  "status": "completed",
  "result_count": 1
}
```

### 결과 조회

```bash
curl http://127.0.0.1:8000/targets/1/results
```

## 테스트 실행

```bash
python -m unittest tests/test_backend_cleanup.py
```

## 자주 겪는 문제

- `connection to server at "localhost", port 5432 failed`
  PostgreSQL이 아직 올라오지 않았거나 `.env`의 `DATABASE_URL`이 현재 Docker 설정과 다를 때 발생합니다. `docker compose up -d` 상태와 `.env` 값을 함께 확인하세요.
- 시드 적재 결과가 `Inserted: 0`, `Skipped: N`
  실패가 아니라 이미 같은 CVE 시드 데이터가 들어 있다는 뜻입니다. 그대로 진행해도 됩니다.

## 디렉터리 구조

```text
app/
  api/routes/         FastAPI 라우트
  core/               설정, DB 연결, 공통 상수
  models/             SQLAlchemy 모델
  repositories/       DB 접근 계층
  scanner/            CVE 매칭 로직
  schemas/            요청/응답 스키마
  seeds/              예시 CVE 시드 데이터
  services/           애플리케이션 서비스 계층
alembic/              마이그레이션
tests/                단위 테스트
```

## 주의 사항

이 프로젝트는 방어적 보안 연구와 CVE 매핑 흐름 검증을 위한 백엔드 PoC입니다. 운영 환경용 스캐너나 익스플로잇 도구로 소개하면 안 됩니다.

## 향후 개선 방향

- 시드 데이터 대신 실제 CVE 수집 파이프라인 연동
- 버전 비교 및 정규화 로직 고도화
- 비동기 또는 백그라운드 스캔 처리 추가
- 인증 및 사용자/프로젝트 단위 분리
- API 문서 예시와 CI 검증 추가
