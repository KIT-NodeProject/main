import json
from pathlib import Path

from app.core.database import SessionLocal
from app.models.cve_catalog import CVECatalog


SEED_FILE = Path(__file__).with_name("cve_seed.json")


def load_seed_data() -> list[dict]:
    return json.loads(SEED_FILE.read_text(encoding="utf-8"))


def main() -> None:
    seed_data = load_seed_data()
    db = SessionLocal()
    inserted_count = 0
    skipped_count = 0

    try:
        for item in seed_data:
            existing_cve = db.get(CVECatalog, item["cve_id"])
            if existing_cve is not None:
                skipped_count += 1
                continue

            db.add(CVECatalog(**item))
            inserted_count += 1

        db.commit()
    finally:
        db.close()

    print(f"Inserted: {inserted_count}")
    print(f"Skipped: {skipped_count}")


if __name__ == "__main__":
    main()
