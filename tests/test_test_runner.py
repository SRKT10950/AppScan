import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from app.test_runner import (
    load_mapping,
    save_mapping,
    scan_workspace_classes,
    detect_test_classes_for,
    resolve_tests_for_classes,
    run_selective_tests
)


class TestRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_and_save_mapping(self):
        mapping_file = self.root / ".appscan" / "test-mapping.json"
        self.assertEqual(load_mapping(mapping_file), {})

        data = {"AccountService": ["AccountServiceTest", "AccountIntegrationTest"]}
        save_mapping(mapping_file, data)
        self.assertTrue(mapping_file.exists())
        loaded = load_mapping(mapping_file)
        self.assertEqual(loaded, {"AccountService": sorted(data["AccountService"])})

    def test_load_mapping_corrupt(self):
        mapping_file = self.root / ".appscan" / "test-mapping.json"
        mapping_file.parent.mkdir(parents=True, exist_ok=True)
        mapping_file.write_text("invalid json content", encoding="utf-8")
        self.assertEqual(load_mapping(mapping_file), {})

    def test_scan_workspace_classes(self):
        classes_dir = self.root / "force-app" / "main" / "default" / "classes"
        classes_dir.mkdir(parents=True, exist_ok=True)

        (classes_dir / "ContactService.cls").write_text(
            "public with sharing class ContactService {\n    public void doWork() {}\n}\n",
            encoding="utf-8"
        )
        (classes_dir / "ContactServiceTest.cls").write_text(
            "@isTest\nprivate class ContactServiceTest {\n    @isTest static void testWork() {}\n}\n",
            encoding="utf-8"
        )

        source_classes, test_classes = scan_workspace_classes(self.root)
        self.assertIn("ContactService", source_classes)
        self.assertIn("ContactServiceTest", test_classes)
        self.assertNotIn("ContactServiceTest", source_classes)
        self.assertNotIn("ContactService", test_classes)

    def test_detect_test_classes_by_name(self):
        classes_dir = self.root / "classes"
        classes_dir.mkdir(parents=True, exist_ok=True)

        (classes_dir / "OrderService.cls").write_text("public class OrderService {}", encoding="utf-8")
        (classes_dir / "OrderServiceTest.cls").write_text("@isTest class OrderServiceTest {}", encoding="utf-8")

        source_classes, test_classes = scan_workspace_classes(self.root)
        detected = detect_test_classes_for("OrderService", self.root, test_classes)
        self.assertEqual(detected, ["OrderServiceTest"])

    def test_detect_test_classes_by_reference(self):
        classes_dir = self.root / "classes"
        classes_dir.mkdir(parents=True, exist_ok=True)

        (classes_dir / "PaymentGateway.cls").write_text("public class PaymentGateway {}", encoding="utf-8")
        (classes_dir / "BillingIntegrationSuite.cls").write_text(
            "@isTest class BillingIntegrationSuite {\n    @isTest static void testPay() {\n        PaymentGateway gw = new PaymentGateway();\n    }\n}",
            encoding="utf-8"
        )

        source_classes, test_classes = scan_workspace_classes(self.root)
        detected = detect_test_classes_for("PaymentGateway", self.root, test_classes)
        self.assertIn("BillingIntegrationSuite", detected)

    def test_resolve_tests_caching(self):
        mapping_file = self.root / ".appscan" / "test-mapping.json"
        # Pre-seed mapping
        save_mapping(mapping_file, {"InvoiceHelper": ["CachedInvoiceTest"]})

        # Calling resolve_tests_for_classes should return cached mapping without scanning filesystem
        resolved, mapping = resolve_tests_for_classes(["InvoiceHelper"], self.root, mapping_file)
        self.assertEqual(resolved, ["CachedInvoiceTest"])
        self.assertEqual(mapping.get("InvoiceHelper"), ["CachedInvoiceTest"])

    def test_resolve_tests_auto_discovery(self):
        classes_dir = self.root / "classes"
        classes_dir.mkdir(parents=True, exist_ok=True)
        (classes_dir / "UserService.cls").write_text("public class UserService {}", encoding="utf-8")
        (classes_dir / "UserServiceTest.cls").write_text("@isTest class UserServiceTest {}", encoding="utf-8")

        mapping_file = self.root / ".appscan" / "test-mapping.json"
        resolved, mapping = resolve_tests_for_classes(["UserService"], self.root, mapping_file)
        self.assertEqual(resolved, ["UserServiceTest"])
        self.assertEqual(mapping.get("UserService"), ["UserServiceTest"])

        # Check it was written to disk
        persisted = load_mapping(mapping_file)
        self.assertEqual(persisted.get("UserService"), ["UserServiceTest"])

    @patch("app.test_runner.subprocess.run")
    @patch("app.test_runner.shutil.which")
    def test_run_selective_tests(self, mock_which, mock_run):
        mock_which.return_value = "sf"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "result": {
                    "coverage": {
                        "coverage": [
                            {"name": "UserService", "numLinesCovered": 10, "numLinesUncovered": 2}
                        ]
                    }
                }
            }),
            stderr=""
        )

        out_dir = self.root / ".appscan"
        cov = run_selective_tests(["UserServiceTest"], self.root, target_org="test-org", output_dir=out_dir)
        self.assertIsNotNone(cov)
        self.assertEqual(len(cov["files"]), 1)
        self.assertEqual(cov["files"][0]["covered_lines"], 10)
        self.assertEqual(cov["files"][0]["uncovered_lines"], 2)
        self.assertTrue((out_dir / "coverage.json").exists())


if __name__ == "__main__":
    unittest.main()
