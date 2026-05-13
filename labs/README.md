# Scanner Test Labs

This directory contains local targets for validating the PoC scanner in this repository.

These labs are intentionally vulnerable. Run them only in a local development environment.

## Labs

- `broken-access-control`: endpoint authorization and IDOR validation target.
- `spring-CVE-2022-22947`: Spring Cloud Gateway CVE-2022-22947 validation target.
- `next-CVE-2025-29927`: Next.js middleware bypass validation target.
- `tas-legacy`: PHP/MySQL legacy vulnerable and secure comparison app.

## Run

Create the shared Docker network once before starting the scanner or labs:

```sh
docker network create scanner-lab-net
```

Each lab is self-contained and should be started from its own directory:

```sh
cd labs/broken-access-control
docker compose up --build
```

Use `docker compose down` from the same lab directory when finished.

When using the shared Docker network, scan these internal URLs from the scanner:

```text
broken-access-control: http://broken-access-control-lab:9000
spring-CVE-2022-22947: http://spring-cve-2022-22947-lab:8080
next-CVE-2025-29927: http://next-cve-2025-29927-lab:3000
tas-legacy: http://tas-legacy-lab
```

For scanner processes running outside Docker, use the host-exposed ports instead.
