from app.scanner.matcher import match_cves


def build_scan_results(
    stack_name: str,
    version: str,
    cve_items: list[dict],
) -> list[dict]:
    matched_cves = match_cves(
        stack_name=stack_name,
        version=version,
        cve_items=cve_items,
    )

    results = []

    for item in matched_cves:
        start_version = item.get("affected_version_start") or "unknown"
        end_version = item.get("affected_version_end") or "unknown"

        results.append(
            {
                "vuln_category": "cve_match",
                "cve_id": item["cve_id"],
                "severity": item["severity"],
                "description": item["summary"],
                "evidence": (
                    f"{stack_name} {version} matched affected versions "
                    f"{start_version} to {end_version}"
                ),
                "status": "detected",
            }
        )

    return results
