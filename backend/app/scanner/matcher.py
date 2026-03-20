import re


def parse_version(version: str) -> list[int]:
    return [int(part) for part in re.findall(r"\d+", version)]


def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version(left)
    right_parts = parse_version(right)

    max_length = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (max_length - len(left_parts)))
    right_parts.extend([0] * (max_length - len(right_parts)))

    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def is_version_in_range(
    version: str,
    start_version: str | None,
    end_version: str | None,
) -> bool:
    if start_version and compare_versions(version, start_version) < 0:
        return False

    if end_version and compare_versions(version, end_version) > 0:
        return False

    return True


def match_cves(stack_name: str, version: str, cve_items: list[dict]) -> list[dict]:
    matched_items = []

    for item in cve_items:
        if item["product_name"].lower() != stack_name.lower():
            continue

        if is_version_in_range(
            version=version,
            start_version=item.get("affected_version_start"),
            end_version=item.get("affected_version_end"),
        ):
            matched_items.append(item)

    return matched_items
