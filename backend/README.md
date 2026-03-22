## 구현 범위

- `POST /api/v1/scans`로 대상 URL과 스택 정보를 받아 스캔 실행
- `GET /api/v1/scans/{scan_run_id}`로 상태 및 요약 조회
- `GET /api/v1/scans/{scan_run_id}/results`로 상세 결과 조회
- `GET /reports/{scan_run_id}`로 HTML 리포트 조회
- 파일 기반 PoC Registry와 서브프로세스 실행 방식 적용

## 기술 스택

- FastAPI
- SQLAlchemy
- Jinja2
- SQLite

## 실행 방법

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

서버 실행 후 아래 흐름으로 확인할 수 있습니다.

1. `POST /api/v1/scans`
2. `GET /api/v1/scans/{scan_run_id}`
3. `GET /api/v1/scans/{scan_run_id}/results`
4. `GET /reports/{scan_run_id}`

## 예시 요청

```json
{
  "base_url": "https://example.com",
  "stack_name": "Nginx",
  "stack_version": "1.18.0"
}
```

## 참고

- PoC는 `backend/pocs/*/metadata.yaml`과 `runner.py` 조합으로 등록됩니다.
- 초기 프로토타입이므로 샘플 PoC 2개를 포함하고 있으며, 실제 운영 전에는 검증된 진단 로직으로 교체해야 합니다.


# 백엔드 개요

이 폴더는 보안 스캐너 프로토타입의 백엔드 구현을 담고 있습니다.

핵심 흐름은 다음과 같습니다.

1. API가 대상 URL과 스택 정보를 입력받습니다.
2. 입력값을 DB에 저장하고 `scan_run`을 생성합니다.
3. 백그라운드 작업이 스택/버전에 맞는 PoC를 찾습니다.
4. 각 PoC를 서브프로세스로 실행하고 결과를 저장합니다.
5. API와 HTML 리포트에서 결과를 조회합니다.

## 폴더 구조

```text
backend/
  app/
    main.py                # FastAPI 엔트리포인트
    config.py              # 환경설정
    database.py            # DB 연결 및 세션 생성
    models.py              # SQLAlchemy 모델
    schemas.py             # API 요청/응답 스키마
    services/
      orchestrator.py      # 스캔 작업 실행 흐름
      registry.py          # metadata.yaml을 읽어 PoC 매칭
      runner.py            # PoC 서브프로세스 실행
      reporter.py          # HTML 리포트 렌더링
  pocs/
    nginx_header_version_probe/
      metadata.yaml        # 적용 스택/버전 조건
      runner.py            # 실제 PoC 코드
    springboot_actuator_exposure/
      metadata.yaml
      runner.py
  templates/
    report.html            # HTML 리포트 템플릿
  scanner.db               # 기본 SQLite DB 파일
```

## 먼저 보면 좋은 파일

- `app/main.py`
  API 라우트와 전체 진입점을 봅니다.
- `app/services/orchestrator.py`
  스캔이 실제로 어떻게 실행되는지 봅니다.
- `app/services/registry.py`
  어떤 PoC가 선택되는지 봅니다.
- `app/services/runner.py`
  PoC를 어떤 방식으로 실행하고 결과를 정규화하는지 봅니다.
- `pocs/*/runner.py`
  개별 PoC 로직을 봅니다.

## 주요 API

- `POST /api/v1/scans`
  스캔 생성
- `GET /api/v1/scans/{scan_run_id}`
  상태 조회
- `GET /api/v1/scans/{scan_run_id}/results`
  상세 결과 조회
- `GET /reports/{scan_run_id}`
  HTML 리포트 조회

## 실행 방법

저장소 루트에서 실행합니다.

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8001
```

확인 주소:

- `http://127.0.0.1:8001/docs`
- `http://127.0.0.1:8001/reports/{scan_run_id}`

## DB와 설정

- 기본 DB는 `backend/scanner.db`를 사용합니다.
- 환경변수 `SCANNER_DATABASE_URL`로 DB 경로를 바꿀 수 있습니다.
- PoC 경로는 `SCANNER_POCS_DIR`, 템플릿 경로는 `SCANNER_TEMPLATES_DIR`로 바꿀 수 있습니다.

## PoC가 동작하는 방식

1. `registry.py`가 `pocs/*/metadata.yaml`을 읽습니다.
2. 입력된 `stack_name`, `stack_version`과 일치하는 PoC만 고릅니다.
3. `runner.py`가 PoC 입력값을 임시 JSON 파일로 만들고 `runner.py --input <file>` 형태로 실행합니다.
4. PoC는 표준 JSON 한 개를 stdout으로 출력해야 합니다.
5. 결과는 `scan_results` 테이블에 저장됩니다.

## 새 PoC 추가 방법

1. `backend/pocs/<poc_name>/` 폴더를 만듭니다.
2. `metadata.yaml`에 스택명, 버전 조건, 심각도, 엔트리포인트를 적습니다.
3. `runner.py`에서 입력 JSON을 읽고 결과 JSON을 stdout으로 출력합니다.

예시 출력 형식:

```json
{
  "poc_name": "example_probe",
  "vulnerable": false,
  "vuln_category": "CVE",
  "cve_id": null,
  "severity": "Low",
  "description": "Example result",
  "evidence": "HTTP 200",
  "raw_output": "",
  "status": "NotFound"
}
```

## 참고

- 현재 포함된 PoC는 문서 구현용 샘플입니다.
- 실제 운영용 진단 로직으로 쓰려면 오탐/누락 검증과 안전성 점검이 더 필요합니다.
