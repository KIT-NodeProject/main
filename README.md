# Security Scanner Prototype

`docs/`에 정리된 요구사항을 기준으로, 입력값 저장 -> PoC 실행 -> 결과 조회/리포트 렌더링 흐름을 갖는 백엔드 프로토타입을 구현한 저장소입니다.

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
