# Security Scanner Documentation

이 문서는 웹 서비스 보안 진단 시스템의 핵심 요구사항과 데이터베이스 설계를 정리한 문서 모음입니다.

## 문서 구성

- [Use Cases](./use-cases.md): 사용자 흐름과 예외 흐름 정리
- [Database Design](./database-design.md): 주요 테이블, 관계, 컬럼 정의 정리
- [Backend Prototype Design](./backend-prototype-design.md): 입력, PoC 실행, 웹 리포트 출력 중심의 백엔드 설계

## 범위

다음 기능 범위를 기준으로 작성되었습니다.

- 검사 대상 등록
- 검사 범위 설정
- 서버 스택 및 버전 식별
- 인증 정보 설정 및 로그인 상태 확보
- 보안 스캔 실행
- 결과 조회 및 리포트 출력
