import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.constants import (
    IDENTIFY_METHOD_MANUAL_INPUT,
    TARGET_STATUS_COMPLETED,
)
from app.models.base import Base
from app.models.cve_catalog import CVECatalog
from app.repositories.target_repository import (
    get_target_by_id,
    get_tech_stack_by_target_id,
)
from app.schemas.target import TargetCreate
from app.services.result_service import get_results_for_target
from app.services.scan_service import run_scan_for_target
from app.services.target_service import create_target_with_stack


class BackendCleanupTests(unittest.TestCase):
    def setUp(self):
        # Keep tests isolated from the local Postgres instance.
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def build_target_data(
        self,
        base_url: str = "https://example.com",
        stack_name: str = "nginx",
        version: str = "1.18.0",
    ) -> TargetCreate:
        return TargetCreate.model_validate(
            {
                "base_url": base_url,
                "tech_stack": {
                    "stack_name": stack_name,
                    "version": version,
                },
            }
        )

    def seed_matching_cve(self, cve_id: str = "CVE-2023-0001") -> None:
        self.db.add(
            CVECatalog(
                cve_id=cve_id,
                product_name="nginx",
                vendor_name="NGINX",
                affected_version_start="1.16.0",
                affected_version_end="1.18.0",
                severity="high",
                summary="Example vulnerability affecting nginx.",
                reference_url=f"https://example.com/{cve_id}",
            )
        )
        self.db.commit()

    def test_create_target_defaults_identify_method_to_manual_input(self):
        target = create_target_with_stack(
            db=self.db,
            target_data=self.build_target_data(),
        )

        tech_stack = get_tech_stack_by_target_id(self.db, target.target_id)

        self.assertIsNotNone(tech_stack)
        self.assertEqual(target.tech_stack.identify_method, IDENTIFY_METHOD_MANUAL_INPUT)
        self.assertEqual(tech_stack.identify_method, IDENTIFY_METHOD_MANUAL_INPUT)

    def test_run_scan_for_target_marks_target_completed(self):
        target = create_target_with_stack(
            db=self.db,
            target_data=self.build_target_data(),
        )
        self.seed_matching_cve()

        scan_results = run_scan_for_target(self.db, target.target_id)
        saved_target = get_target_by_id(self.db, target.target_id)

        self.assertEqual(len(scan_results), 1)
        self.assertIsNotNone(saved_target)
        self.assertEqual(saved_target.status, TARGET_STATUS_COMPLETED)

    def test_happy_path_results_query_returns_saved_result(self):
        target = create_target_with_stack(
            db=self.db,
            target_data=self.build_target_data(),
        )
        self.seed_matching_cve(cve_id="CVE-2023-9999")

        run_scan_for_target(self.db, target.target_id)
        results = get_results_for_target(self.db, target.target_id)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2023-9999")

    def test_rescan_replaces_existing_results_instead_of_duplicating(self):
        target = create_target_with_stack(
            db=self.db,
            target_data=self.build_target_data(),
        )
        self.seed_matching_cve(cve_id="CVE-2023-0001")

        first_results = run_scan_for_target(self.db, target.target_id)

        self.seed_matching_cve(cve_id="CVE-2023-0002")
        second_results = run_scan_for_target(self.db, target.target_id)
        saved_results = get_results_for_target(self.db, target.target_id)

        self.assertEqual(len(first_results), 1)
        self.assertEqual(len(second_results), 2)
        self.assertEqual(len(saved_results), 2)
        self.assertEqual(
            [result.cve_id for result in saved_results],
            ["CVE-2023-0001", "CVE-2023-0002"],
        )


if __name__ == "__main__":
    unittest.main()
