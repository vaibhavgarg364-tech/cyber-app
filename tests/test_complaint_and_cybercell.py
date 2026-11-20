import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes.compliance import (
    _maps_link,
    _office_payload,
    _distance_km,
    _find_nearest_state_by_gps,
    _all_cybercell_states,
    _extract_complaint_entities,
    _generate_fallback_complaint,
    get_cybercell,
    generate_complaint,
    ComplaintDraftRequest,
)


class TestComplaintAndCybercell(unittest.TestCase):
    def test_maps_link_omits_origin_and_uses_verified_destination(self):
        """Directions URL must omit origin completely (relying on Maps live location) and use verified address."""
        link = _maps_link(
            lat=16.4305,
            lng=80.5689,
            address="CID Headquarters, Mangalagiri, Andhra Pradesh",
            user_lat=16.5000,
            user_lng=80.6000,
        )
        self.assertTrue(link.startswith("https://www.google.com/maps/dir/?"))
        self.assertNotIn("origin=", link)
        self.assertNotIn("16.5", link)
        self.assertNotIn("80.6", link)
        self.assertNotIn("16.4305", link)
        self.assertIn("destination=CID%20Headquarters%2C%20Mangalagiri%2C%20Andhra%20Pradesh", link)
        self.assertIn("travelmode=driving", link)
        self.assertIn("api=1", link)

    def test_maps_link_place_id_strategy(self):
        """When place_id is provided, directions URL includes destination_place_id alongside destination."""
        link = _maps_link(
            address="Cyber Crime Police Station",
            place_id="ChIJxyz12345",
        )
        self.assertTrue(link.startswith("https://www.google.com/maps/dir/?"))
        self.assertIn("destination_place_id=ChIJxyz12345", link)
        self.assertIn("destination=Cyber%20Crime%20Police%20Station", link)
        self.assertNotIn("origin=", link)
        self.assertIn("travelmode=driving", link)

    def test_maps_link_fallback_without_inventing_coordinates(self):
        """Missing or incomplete address falls back safely without inventing fake coordinates."""
        # Fallback with city
        link_city = _maps_link(lat=None, lng=None, address="", city="Dehradun")
        self.assertTrue(link_city.startswith("https://www.google.com/maps/dir/?"))
        self.assertIn("destination=Cyber%20Crime%20Police%20Station%2C%20Dehradun", link_city)
        self.assertNotIn("origin=", link_city)

        # Fallback with completely missing metadata
        link_empty = _maps_link(lat=None, lng=None, address=None, city=None)
        self.assertTrue(link_empty.startswith("https://www.google.com/maps/dir/?"))
        self.assertIn("destination=Cyber%20Crime%20Police%20Station", link_empty)
        self.assertNotIn("origin=", link_empty)

    def test_dehradun_station_record_consistency_and_directions(self):
        """Intended Dehradun station name, destination address, and link derive from same record without origin."""
        resp = get_cybercell(
            state="Uttarakhand",
            lat=30.3165,
            lng=78.0322,
            is_gps=True,
        )
        self.assertEqual(resp.get("state"), "Uttarakhand")
        hq = resp.get("hq", {})
        nearest = resp.get("nearestOffice", {})
        self.assertEqual(hq.get("city"), "Dehradun")
        self.assertIn("Gandhi Road", hq.get("address", ""))
        self.assertIn("248001", hq.get("address", ""))

        link = nearest.get("googleMapsLink", "")
        self.assertTrue(link.startswith("https://www.google.com/maps/dir/?"))
        self.assertNotIn("origin=", link)
        # Approximate routing coordinates must NOT be used as destination
        self.assertNotIn("destination=30.3165", link)
        self.assertNotIn("destination=78.0322", link)
        # Verified station address must be present in destination parameter
        self.assertIn("Gandhi%20Road", link)
        self.assertIn("248001", link)
        self.assertIn("travelmode=driving", link)
        self.assertIn("api=1", link)

    def test_nearest_state_by_gps_dehradun_returns_uttarakhand(self):
        """GPS coordinates of Dehradun (Uttarakhand) must resolve to Uttarakhand even if state='Maharashtra'."""
        states = _all_cybercell_states()
        dehradun_lat = 30.3165
        dehradun_lng = 78.0322

        # Direct GPS helper
        nearest = _find_nearest_state_by_gps(states, dehradun_lat, dehradun_lng)
        self.assertIsNotNone(nearest)
        self.assertEqual(nearest.get("name"), "Uttarakhand")

        # Via get_cybercell route with is_gps=True overriding default state
        resp = get_cybercell(
            state="Maharashtra",
            lat=dehradun_lat,
            lng=dehradun_lng,
            is_gps=True,
        )
        self.assertEqual(resp.get("state"), "Uttarakhand")
        self.assertIsNotNone(resp.get("hq", {}).get("distanceKm"))
        self.assertLess(resp["hq"]["distanceKm"], 50.0)
        self.assertNotIn("origin=", resp["hq"]["googleMapsLink"])
        self.assertIn("travelmode=driving", resp["hq"]["googleMapsLink"])

    def test_nearest_state_manual_selection_preserved_when_not_gps(self):
        """When is_gps is False and user specifically selected a state, respect user selection."""
        resp = get_cybercell(
            state="Goa",
            lat=30.3165,
            lng=78.0322,
            is_gps=False,
        )
        self.assertEqual(resp.get("state"), "Goa")
        # Distance from user coords to Goa HQ should still be calculated
        self.assertIsNotNone(resp.get("hq", {}).get("distanceKm"))
        self.assertGreater(resp["hq"]["distanceKm"], 1000.0)

    def test_extract_complaint_entities(self):
        """Regex extractor correctly isolates amounts, transaction IDs, dates, phones, handles, and URLs."""
        narrative = (
            "On 14th March 2026, I was defrauded of Rs. 65,000 via GooglePay UPI transaction "
            "TXN987654321012 after receiving a WhatsApp call from +91 9876543210 posing as bank manager. "
            "They directed me to fake portal https://secure-bank-login.xyz and UPI handle fraudster@okhdfc."
        )
        entities = _extract_complaint_entities(narrative)
        self.assertIn("65,000", entities["amounts"])
        self.assertTrue(any("987654321012" in txn for txn in entities["transactionIds"]))
        self.assertTrue(any("14th March 2026" in d for d in entities["dates"]))
        self.assertTrue(any("9876543210" in p for p in entities["phoneNumbers"]))
        self.assertTrue(any("fraudster@okhdfc" in h for h in entities["handlesOrUpiIds"]))
        self.assertTrue(any("https://secure-bank-login.xyz" in u for u in entities["urls"]))

    def test_generate_fallback_complaint(self):
        """Deterministic fallback generates comprehensive legal complaint preserving narrative and facts."""
        narrative = "Lost Rs 25,000 on 12-02-2026 via UPI ref 123456789012"
        entities = _extract_complaint_entities(narrative)
        draft = _generate_fallback_complaint(
            incident_desc=narrative,
            incident_type="upi_fraud",
            user_state="Karnataka",
            entities=entities,
        )
        self.assertIn("To,", draft)
        self.assertIn("The Station House Officer,", draft)
        self.assertIn("Cyber Crime Police Station,", draft)
        self.assertIn("Karnataka", draft)
        self.assertIn("Section 66D, Information Technology Act, 2000", draft)
        self.assertIn("Section 318(4), Bharatiya Nyaya Sanhita", draft)
        self.assertIn("1930 mechanism", draft)
        self.assertIn("Lost Rs 25,000 on 12-02-2026 via UPI ref 123456789012", draft)
        self.assertIn("Rs. 25,000", draft)

    def test_generate_complaint_route_fallback(self):
        """generate_complaint route succeeds cleanly via fallback when Gemini is unavailable or not set."""
        with patch("config.settings.gemini_api_key", ""):
            payload = ComplaintDraftRequest(
                incidentDesc="I received a phishing email on 15/01/2026 with link https://fake-tax.in and entered my credentials.",
                incidentType="phishing",
                userState="Delhi",
            )
            result = generate_complaint(payload)
            self.assertTrue(result["success"])
            self.assertEqual(result["source"], "fallback")
            self.assertIn("To,", result["draft"])
            self.assertIn("Station House Officer", result["draft"])
            self.assertIn("https://fake-tax.in", result["draft"])

    def test_generate_complaint_route_gemini_success(self):
        """generate_complaint route returns Gemini draft when Gemini generation succeeds."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = (
            "To,\nThe Station House Officer,\nCyber Crime Police Station, Maharashtra\n\n"
            "Subject: Formal Police Complaint Regarding UPI Financial Fraud\n\n"
            "Respected Sir,\nI lodge this formal complaint regarding Rs 50,000 defrauded on 10th Jan 2026."
        )
        mock_client.models.generate_content.return_value = mock_response

        with patch("config.settings.gemini_api_key", "fake-key"), \
             patch("google.genai.Client", return_value=mock_client):
            payload = ComplaintDraftRequest(
                incidentDesc="Defrauded of Rs 50,000 on 10th Jan 2026 via UPI transaction REF998877665544.",
                incidentType="upi_fraud",
                userState="Maharashtra",
            )
            result = generate_complaint(payload)
            self.assertTrue(result["success"])
            self.assertEqual(result["source"], "gemini")
            self.assertIn("Formal Police Complaint", result["draft"])


if __name__ == "__main__":
    unittest.main()
