import os
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes import detectors
from routes.detectors import (
    extract_play_store_package,
    _find_app_record,
    AppCheckRequest,
    check_app,
)


class TestAppAuthenticity(unittest.TestCase):
    def setUp(self):
        self.gov_apps = detectors.GOV_APPS_DB.get("apps", [])

    def test_catalog_aadhaar_not_facebook(self):
        """Verify that Aadhaar is mapped to in.gov.uidai.pehchaan, NOT com.facebook.id."""
        for app in self.gov_apps:
            if app["name"].lower() == "aadhaar":
                self.assertNotEqual(app.get("officialPackage"), "com.facebook.id")
                self.assertEqual(app.get("officialPackage"), "in.gov.uidai.pehchaan")
                self.assertIn("in.gov.uidai.pehchaan", app.get("playStoreLink", ""))

    def test_catalog_maadhaar_package(self):
        """Verify mAadhaar has official package in.gov.uidai.mAadhaarPlus."""
        maadhaar_app = next((a for a in self.gov_apps if a["name"] == "mAadhaar"), None)
        self.assertIsNotNone(maadhaar_app)
        self.assertEqual(maadhaar_app.get("officialPackage"), "in.gov.uidai.mAadhaarPlus")
        self.assertIn("in.gov.uidai.mAadhaarPlus", maadhaar_app.get("playStoreLink", ""))

    def test_aadhaar_and_maadhaar_are_distinct(self):
        """Aadhaar and mAadhaar must be distinct apps with different packages."""
        aadhaar_app = next((a for a in self.gov_apps if a["name"] == "Aadhaar"), None)
        maadhaar_app = next((a for a in self.gov_apps if a["name"] == "mAadhaar"), None)
        self.assertIsNotNone(aadhaar_app)
        self.assertIsNotNone(maadhaar_app)
        self.assertNotEqual(aadhaar_app["officialPackage"], maadhaar_app["officialPackage"])

    def test_umang_verified_package(self):
        """UMANG must have package in.gov.umang.negd.g2c."""
        umang_app = next((a for a in self.gov_apps if a["name"] == "UMANG"), None)
        self.assertIsNotNone(umang_app)
        self.assertEqual(umang_app.get("officialPackage"), "in.gov.umang.negd.g2c")

    def test_cowin_and_aarogya_setu_distinct(self):
        """CoWIN and Aarogya Setu must be distinct applications."""
        cowin = next((a for a in self.gov_apps if a["name"] == "CoWIN"), None)
        aarogya = next((a for a in self.gov_apps if a["name"] == "Aarogya Setu"), None)
        self.assertIsNotNone(cowin)
        self.assertIsNotNone(aarogya)
        self.assertEqual(cowin["officialPackage"], "com.cowin.gov.in")
        self.assertEqual(aarogya["officialPackage"], "nic.goi.aarogyasetu")
        self.assertNotEqual(cowin["officialPackage"], aarogya["officialPackage"])

    def test_extract_play_store_package(self):
        """URL parser extracts package ID from standard and complex Google Play URLs."""
        url1 = "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus"
        self.assertEqual(extract_play_store_package(url1), "in.gov.uidai.mAadhaarPlus")

        url2 = "https://play.google.com/store/apps/details?id=in.gov.uidai.pehchaan&hl=en_IN&gl=US"
        self.assertEqual(extract_play_store_package(url2), "in.gov.uidai.pehchaan")

        market_url = "market://details?id=com.digilocker.android"
        self.assertEqual(extract_play_store_package(market_url), "com.digilocker.android")

        direct_pkg = "in.gov.uidai.mAadhaarPlus"
        self.assertEqual(extract_play_store_package(direct_pkg), "in.gov.uidai.mAadhaarPlus")

        # Malformed / unexpected hosts
        self.assertIsNone(extract_play_store_package("https://evil.com/store/apps/details?id=com.fake"))
        self.assertIsNone(extract_play_store_package("https://play.google.com/about"))
        self.assertIsNone(extract_play_store_package(""))
        self.assertIsNone(extract_play_store_package("Just Plain Text"))

    def test_find_app_record_maadhaar_lookup(self):
        """Query for 'mAadhaar' must match mAadhaar, NEVER Aadhaar or com.facebook.id."""
        record, pkg = _find_app_record("mAadhaar")
        self.assertIsNotNone(record)
        self.assertEqual(record["name"], "mAadhaar")
        self.assertEqual(record["officialPackage"], "in.gov.uidai.mAadhaarPlus")
        self.assertNotEqual(record["officialPackage"], "com.facebook.id")

    def test_find_app_record_aadhaar_lookup(self):
        """Query for 'Aadhaar' must match Aadhaar."""
        record, pkg = _find_app_record("Aadhaar")
        self.assertIsNotNone(record)
        self.assertEqual(record["name"], "Aadhaar")
        self.assertEqual(record["officialPackage"], "in.gov.uidai.pehchaan")

    def test_pasted_play_store_url_resolves_correct_app(self):
        """Pasting a Play Store URL resolves the corresponding package."""
        url = "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus"
        record, pkg = _find_app_record(url)
        self.assertIsNotNone(record)
        self.assertEqual(record["name"], "mAadhaar")
        self.assertEqual(pkg, "in.gov.uidai.mAadhaarPlus")

    def test_conflicting_package_id_and_url(self):
        """Conflicting URL package and explicit packageName are flagged as fake/impersonation."""
        req = AppCheckRequest(
            appName="https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus",
            packageName="com.malicious.impostor",
        )
        resp = check_app(req)
        self.assertEqual(resp["verdict"], "fake")
        self.assertTrue(any("conflict" in r.lower() for r in resp["risks"]))

    def test_non_gov_app_no_unrelated_gov_alternatives(self):
        """Checking a non-government app must NOT return random government apps as alternatives."""
        req = AppCheckRequest(appName="WhatsApp")
        resp = check_app(req)
        # officialAlternatives should not be blindly populated with gov apps
        self.assertEqual(resp["officialAlternatives"], [])
        self.assertIn("playStoreLink", resp)
        # Must not point to com.facebook.id or Aadhaar
        if resp.get("playStoreLink"):
            self.assertNotIn("in.gov.uidai", resp["playStoreLink"])

    def test_top_level_play_store_link_in_response(self):
        """check_app response always includes top-level playStoreLink and lookupStatus."""
        req = AppCheckRequest(appName="mAadhaar")
        resp = check_app(req)
        self.assertEqual(resp["verdict"], "official")
        self.assertEqual(resp["appName"], "mAadhaar")
        self.assertEqual(resp["officialPackage"], "in.gov.uidai.mAadhaarPlus")
        self.assertEqual(
            resp.get("playStoreLink"),
            "https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus",
        )
        self.assertIn("lookupStatus", resp)


if __name__ == "__main__":
    unittest.main()
