from pathlib import Path
from typing import Any, Dict, List, Optional
from math import asin, cos, radians, sin, sqrt
import re
import json
import logging
from urllib.parse import quote, quote_plus, urlencode
from datetime import datetime
import concurrent.futures

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from config import load_json_file, settings
from routes.utils import safe_request_json

logger = logging.getLogger("veyron-backend")

router = APIRouter(tags=["compliance"])

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HELPLINES_DB = load_json_file(DATA_DIR / "helplines.json")
CYBERCELL_DB = load_json_file(DATA_DIR / "cybercell.json")


class HelplineRequest(BaseModel):
    incidentType: str = Field(min_length=2, max_length=64)
    userState: Optional[str] = None


class ComplaintDraftRequest(BaseModel):
    incidentDesc: str = Field(min_length=10, max_length=5000)
    incidentType: Optional[str] = None
    userState: Optional[str] = None


STATE_ALIASES = {
    "andaman": "Andaman and Nicobar Islands",
    "andaman and nicobar": "Andaman and Nicobar Islands",
    "andaman & nicobar": "Andaman and Nicobar Islands",
    "ap": "Andhra Pradesh",
    "arunachal": "Arunachal Pradesh",
    "cg": "Chhattisgarh",
    "chattisgarh": "Chhattisgarh",
    "daman and diu": "Dadra and Nagar Haveli and Daman and Diu",
    "dadra and nagar haveli": "Dadra and Nagar Haveli and Daman and Diu",
    "dnhdd": "Dadra and Nagar Haveli and Daman and Diu",
    "j&k": "Jammu and Kashmir",
    "jammu & kashmir": "Jammu and Kashmir",
    "mp": "Madhya Pradesh",
    "mh": "Maharashtra",
    "orissa": "Odisha",
    "pondicherry": "Puducherry",
    "tn": "Tamil Nadu",
    "ts": "Telangana",
    "uk": "Uttarakhand",
    "uttrakhand": "Uttarakhand",
    "up": "Uttar Pradesh",
    "wb": "West Bengal",
}


def _state_from_ip(ip: str) -> str:
    if not ip or ip in {"127.0.0.1", "::1"}:
        return "Delhi"
    data = safe_request_json("GET", f"https://ipapi.co/{ip}/json/", timeout=4)
    region = (data or {}).get("region")
    return str(region) if region else "Delhi"


def _incident_actions(incident: str) -> Dict[str, Any]:
    mapping = {
        "upi_fraud": "Bank ko turant call karein, 1930 dial karein, transaction ID save karein.",
        "fake_app": "App uninstall karein, permissions revoke karein, cyber portal par complaint karein.",
        "deepfake": "Evidence save karein, platform report karein, FIR initiate karein.",
        "sextortion": "Payment na karein, chat/screenshots preserve karein, 1930 aur cybercrime.gov.in use karein.",
        "job_scam": "Advance payment stop karein, recruiter details report karein.",
        "loan_fraud": "Unauthorized app remove karein, contacts permissions revoke karein.",
    }
    return {
        "timeline": mapping.get(
            incident,
            "Immediate fraud containment karein, 1930 call karein, online complaint file karein.",
        ),
        "evidenceChecklist": [
            "Screenshots of chats/messages",
            "Transaction IDs, UTR numbers, bank statements",
            "Phone numbers, handles, URLs, email headers",
            "App package name, app link, and install source",
            "Timeline of events with exact timestamps",
        ],
        "urgencyScore": (
            95
            if incident in {"upi_fraud", "sextortion", "loan_fraud"}
            else 80 if incident in {"deepfake", "job_scam"} else 65
        ),
    }


def _all_cybercell_states() -> List[Dict[str, Any]]:
    return CYBERCELL_DB.get("states", [])


def _normalize_state_name(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    needle = value.strip().lower()
    if not needle:
        return None
    if needle in STATE_ALIASES:
        return STATE_ALIASES[needle]
    for item in _all_cybercell_states():
        name = item.get("name", "")
        if name.lower() == needle:
            return name
    for item in _all_cybercell_states():
        name = item.get("name", "")
        if needle in name.lower() or name.lower() in needle:
            return name
    return value


def _distance_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius = 6371.0
    dlat = radians(lat2 - lat1)
    dlng = radians(lng2 - lng1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlng / 2) ** 2
    return 2 * radius * asin(sqrt(a))


def _maps_link(
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    address: Optional[str] = None,
    user_lat: Optional[float] = None,
    user_lng: Optional[float] = None,
    city: Optional[str] = None,
    office_name: Optional[str] = None,
    place_id: Optional[str] = None,
) -> str:
    """
    Constructs an official Google Maps Directions URL:
    https://www.google.com/maps/dir/?api=1&destination=ENCODED_DESTINATION&travelmode=driving

    The origin parameter is omitted entirely so Google Maps calculates routes from
    the user's live device location ('Your location') rather than freezing to static browser coordinates.
    Destination uses the verified station address or Place ID rather than approximate
    city-center routing coordinates.
    """
    dest_str = ""
    if address and address.strip():
        dest_str = address.strip()
    elif office_name and office_name.strip():
        dest_str = office_name.strip()
    elif city and city.strip():
        dest_str = f"Cyber Crime Police Station, {city.strip()}"
    else:
        dest_str = "Cyber Crime Police Station"

    params: Dict[str, str] = {
        "api": "1",
        "destination": dest_str,
        "travelmode": "driving",
    }
    if place_id and str(place_id).strip():
        params["destination_place_id"] = str(place_id).strip()

    return f"https://www.google.com/maps/dir/?{urlencode(params, quote_via=quote)}"


def _office_payload(office: Dict[str, Any], user_lat: Optional[float], user_lng: Optional[float]) -> Dict[str, Any]:
    lat = office.get("lat")
    lng = office.get("lng")
    distance = None
    if user_lat is not None and user_lng is not None and lat is not None and lng is not None:
        distance = round(_distance_km(user_lat, user_lng, float(lat), float(lng)), 1)
    return {
        **office,
        "distanceKm": distance,
        "googleMapsLink": _maps_link(
            lat=lat,
            lng=lng,
            address=office.get("address", ""),
            user_lat=user_lat,
            user_lng=user_lng,
            city=office.get("city"),
            office_name=office.get("name"),
            place_id=office.get("place_id") or office.get("placeId"),
        ),
    }


def _nearest_office(state_record: Dict[str, Any], lat: Optional[float], lng: Optional[float]) -> Dict[str, Any]:
    offices = [state_record.get("hq", {})] + state_record.get("offices", [])
    valid_offices = [o for o in offices if o]
    if not valid_offices:
        return {}
    if lat is None or lng is None:
        return _office_payload(valid_offices[0], lat, lng)
    return min(
        (_office_payload(office, lat, lng) for office in valid_offices),
        key=lambda item: item["distanceKm"] if item["distanceKm"] is not None else float("inf"),
    )


def _state_distance_km(state_record: Dict[str, Any], lat: float, lng: float) -> float:
    offices = [state_record.get("hq", {})] + state_record.get("offices", [])
    distances = []
    for office in offices:
        if office and office.get("lat") is not None and office.get("lng") is not None:
            distances.append(_distance_km(lat, lng, float(office["lat"]), float(office["lng"])))
    return min(distances) if distances else float("inf")


def _find_nearest_state_by_gps(states: List[Dict[str, Any]], lat: float, lng: float) -> Optional[Dict[str, Any]]:
    if not states:
        return None
    return min(states, key=lambda s: _state_distance_km(s, lat, lng))


@router.post("/get-cybercell")
def get_cybercell(
    state: Optional[str] = Query(default=None),
    lat: Optional[float] = Query(default=None),
    lng: Optional[float] = Query(default=None),
    is_gps: Optional[bool] = Query(default=False),
) -> Dict[str, Any]:
    states = _all_cybercell_states()
    state_name = _normalize_state_name(state)
    selected = None

    if lat is not None and lng is not None and (is_gps or not state_name):
        selected = _find_nearest_state_by_gps(states, lat, lng)
    elif state_name:
        selected = next((item for item in states if item.get("name", "").lower() == state_name.lower()), None)

    if selected is None and lat is not None and lng is not None:
        selected = _find_nearest_state_by_gps(states, lat, lng)

    if selected is None:
        selected = next((item for item in states if item.get("name") == "Delhi"), states[0] if states else {})

    nearest = _nearest_office(selected, lat, lng) if selected else {}
    offices = [_office_payload(office, lat, lng) for office in selected.get("offices", [])]
    return {
        "state": selected.get("name"),
        "type": selected.get("type"),
        "region": selected.get("region"),
        "hq": _office_payload(selected.get("hq", {}), lat, lng),
        "nearestOffice": nearest,
        "offices": offices,
        "states": [item.get("name") for item in states],
        "metadata": CYBERCELL_DB.get("metadata", {}),
    }


@router.post("/get-helplines")
def get_helplines(payload: HelplineRequest, request: Request) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else ""
    detected_state = payload.userState or _state_from_ip(client_ip)

    primary = {
        "number": "1930",
        "name": "National Cyber Helpline",
        "description": "Call immediately for financial fraud / Financial fraud mein turant call karein.",
        "timeLimit": "60 minutes",
        "callDirectLink": "tel:1930",
    }
    portals = [
        {
            "name": "cybercrime.gov.in",
            "url": "https://cybercrime.gov.in",
            "purpose": "File FIR and online complaints",
            "stepByStep": [
                "Go to site / Website kholein",
                "Click 'File Complaint'",
                "Choose incident type",
                "Upload evidence and submit",
            ],
        },
        {
            "name": "RBI Complaint Portal",
            "url": "https://cms.rbi.org.in",
            "purpose": "UPI and banking fraud",
            "stepByStep": ["Open portal", "Register complaint", "Add bank transaction details", "Submit"],
        },
        {
            "name": "CERT-In",
            "url": "https://www.cert-in.org.in",
            "purpose": "Technical cyber incidents",
            "stepByStep": ["Visit CERT-In", "Navigate incident reporting", "Provide technical details", "Submit"],
        },
        {
            "name": "TRAI",
            "url": "https://www.trai.gov.in",
            "purpose": "SIM swap, spam calls",
            "stepByStep": ["Visit TRAI", "Open consumer complaint", "Submit spam/SIM issue", "Track complaint"],
        },
    ]

    cells = HELPLINES_DB.get("cyberCells", [])
    nearest = next((c for c in cells if c["state"].lower() == detected_state.lower()), None)
    if not nearest:
        nearest = cells[0] if cells else {}
    incident_plan = _incident_actions(payload.incidentType)
    return {
        "primaryAction": primary,
        "portals": portals,
        "nearestCyberCell": nearest,
        "timelineAdvice": incident_plan["timeline"],
        "evidenceChecklist": incident_plan["evidenceChecklist"],
        "urgencyScore": incident_plan["urgencyScore"],
        "priorityBand": (
            "critical"
            if incident_plan["urgencyScore"] >= 90
            else "high" if incident_plan["urgencyScore"] >= 75 else "moderate"
        ),
        "hindiSummary": "Sabse pehle 1930 call karein, phir cybercrime portal par complaint file karein.",
    }


def _extract_complaint_entities(text: str) -> Dict[str, Any]:
    amounts = re.findall(
        r"(?:rs\.?|inr|₹)\s*([\d,]+(?:\.\d+)?)|([\d,]+(?:\.\d+)?)\s*(?:rs\.?|inr|rupees)",
        text,
        re.IGNORECASE,
    )
    cleaned_amounts = []
    for m in amounts:
        val = m[0] or m[1]
        val = val.strip().rstrip(".,")
        if val and val not in cleaned_amounts:
            cleaned_amounts.append(val)

    txn_matches = re.findall(
        r"\b(?:upi(?:\s*ref)?|rrn|txn|transaction(?:\s*id)?|utr|ref(?:\s*no)?)[-:\s#]*([a-zA-Z0-9/_-]{8,35})\b",
        text,
        re.IGNORECASE,
    )
    cleaned_txns = list(dict.fromkeys([m.strip() for m in txn_matches if m.strip()]))

    date_matches = re.findall(
        r"\b(?:\d{1,2}(?:st|nd|rd|th)?\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{2,4}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b",
        text,
        re.IGNORECASE,
    )
    cleaned_dates = list(dict.fromkeys([d.strip() for d in date_matches if d.strip()]))

    phone_matches = re.findall(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b", text)
    cleaned_phones = list(dict.fromkeys([p.strip() for p in phone_matches if p.strip()]))

    handles = re.findall(r"(?:^|\s)(@[a-zA-Z0-9_.]+)", text)
    upi_ids = re.findall(r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b", text)
    all_handles = list(dict.fromkeys([h.strip() for h in handles + upi_ids if h.strip()]))

    urls = re.findall(r"https?://[^\s()\"'<>]+", text)
    cleaned_urls = list(dict.fromkeys([u.strip().rstrip(".,") for u in urls if u.strip()]))

    return {
        "amounts": cleaned_amounts,
        "transactionIds": cleaned_txns,
        "dates": cleaned_dates,
        "phoneNumbers": cleaned_phones,
        "handlesOrUpiIds": all_handles,
        "urls": cleaned_urls,
    }


def _generate_fallback_complaint(
    incident_desc: str,
    incident_type: Optional[str],
    user_state: Optional[str],
    entities: Dict[str, Any],
) -> str:
    category = (incident_type or "").lower()
    subject_map = {
        "upi_fraud": "Complaint Regarding Unauthorized Online Banking / UPI Financial Fraud",
        "fake_app": "Complaint Regarding Fraudulent / Malicious Mobile Application and Identity Theft",
        "deepfake": "Complaint Regarding Deepfake Media Impersonation, Defamation, and Digital Harassment",
        "sextortion": "Complaint Regarding Online Blackmail, Cyber Extortion, and Digital Voyeurism",
        "job_scam": "Complaint Regarding Online Employment / Job Recruitment Fraud",
        "loan_fraud": "Complaint Regarding Illegal Loan App Harassment and Unauthorized Data Access",
    }
    subject = subject_map.get(
        category,
        "Complaint Regarding Online Cyber Crime Incident and Criminal Misuse of Digital Systems",
    )

    legal_sections = []
    if category in {"upi_fraud", "loan_fraud", "job_scam"} or entities.get("amounts"):
        legal_sections.extend([
            "Section 66D, Information Technology Act, 2000 (Punishment for cheating by personation using computer resource)",
            "Section 318(4), Bharatiya Nyaya Sanhita, 2023 / Section 420, Indian Penal Code (Cheating and dishonestly inducing delivery of property)",
        ])
    if category in {"deepfake", "sextortion"}:
        legal_sections.extend([
            "Section 66E, Information Technology Act, 2000 (Violation of privacy / digital voyeurism)",
            "Section 67 / 67A, Information Technology Act, 2000 (Publishing or transmitting obscene/explicit material in electronic form)",
            "Section 351, Bharatiya Nyaya Sanhita, 2023 / Section 503, Indian Penal Code (Criminal Intimidation / Extortion)",
        ])
    if not legal_sections:
        legal_sections.append(
            "Section 66C & 66D, Information Technology Act, 2000 (Identity theft and cheating by computer resource)"
        )

    sections_text = "\n".join(f"• {sec}" for sec in legal_sections)

    amount_str = entities["amounts"][0] if entities.get("amounts") else "[AMOUNT IF APPLICABLE]"
    txn_str = entities["transactionIds"][0] if entities.get("transactionIds") else "[TRANSACTION ID / UTR / REF NUMBER IF APPLICABLE]"
    date_str = entities["dates"][0] if entities.get("dates") else datetime.now().strftime("%d-%m-%Y")
    suspect_contacts = []
    if entities.get("phoneNumbers"):
        suspect_contacts.append(f"Phone: {', '.join(entities['phoneNumbers'])}")
    if entities.get("handlesOrUpiIds"):
        suspect_contacts.append(f"UPI/Social Handles: {', '.join(entities['handlesOrUpiIds'])}")
    if entities.get("urls"):
        suspect_contacts.append(f"Websites/URLs: {', '.join(entities['urls'])}")
    suspect_str = "; ".join(suspect_contacts) if suspect_contacts else "[PHONE / UPI ID / HANDLE / URL OF SUSPECT IF KNOWN]"

    today_str = datetime.now().strftime("%d-%m-%Y")
    state_str = user_state or "[STATE / DISTRICT]"

    draft = f"""To,
The Station House Officer,
Cyber Crime Police Station,
{state_str}

Date: {today_str}

Subject: {subject}

Respected Sir/Madam,

I, [YOUR FULL NAME], son/daughter of [FATHER/GUARDIAN NAME], aged [AGE], residing at [YOUR COMPLETE ADDRESS, CITY, PIN CODE], contact number [YOUR PHONE NUMBER], hereby submit this formal complaint regarding a cyber crime committed against me.

1. STATEMENT OF FACTS:
{incident_desc.strip()}

2. PARTICULARS OF INCIDENT & DIGITAL EVIDENCE:
• Date and Time of Incident: {date_str}
• Total Disputed / Lost Amount: Rs. {amount_str}
• Transaction Reference / UTR / Order ID: {txn_str}
• Suspect Identification (Phone / UPI / Handle / URL): {suspect_str}
• Platform / Medium Used: {category.replace('_', ' ').title() if category else '[NAME OF APP/PORTAL/BANK]'}
• Complainant Bank & Account (if financial): [YOUR BANK NAME & LAST 4 DIGITS OF ACCOUNT NO]

3. APPLICABLE STATUTORY PROVISIONS:
This complaint is lodged under the following provisions of the law:
{sections_text}

4. PRAYER / RELIEF SOUGHT:
In light of the above facts, I earnestly request your office to:
a) Register an official First Information Report (FIR) under the aforementioned legal provisions.
b) Issue an immediate freezing / lien request to the concerned beneficiary banks / payment gateways / UPI nodal desks under the National Cyber Crime Reporting Portal (NCRP) / 1930 mechanism to prevent siphoning of defrauded funds.
c) Issue statutory notice under Section 91 CrPC / Section 94 BNSS to relevant telecom providers and online intermediaries to preserve and furnish digital logs, IP addresses, MAC addresses, and CDRs of the accused.
d) Apprehend the perpetrators and initiate lawful recovery of the defrauded assets.

I hereby declare that the particulars stated above are true and correct to the best of my knowledge and belief. Relevant screenshots, transaction receipts, and digital proofs are enclosed herewith.

Yours faithfully,

(Signature)
Name: [YOUR FULL NAME]
Mobile: [YOUR PHONE NUMBER]
Email: [YOUR EMAIL ADDRESS]
Enclosures: Bank statement / transaction screenshot / communication transcripts"""
    return draft.strip()


@router.post("/generate-complaint")
def generate_complaint(payload: ComplaintDraftRequest) -> Dict[str, Any]:
    entities = _extract_complaint_entities(payload.incidentDesc)
    desc = payload.incidentDesc.strip()
    incident_type = payload.incidentType
    user_state = payload.userState

    api_key = getattr(settings, "gemini_api_key", None)
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            system_instruction = (
                "You are an expert Indian cyber law and cyber forensics legal assistant. "
                "Draft a formal, comprehensive, and legally robust police complaint addressed to the "
                "Station House Officer (SHO), Cyber Crime Police Station, India, ready for submission to "
                "the police or on cybercrime.gov.in.\n\n"
                "RULES:\n"
                "1. Address properly to 'To, The Station House Officer, Cyber Crime Police Station, [State/District]'.\n"
                "2. Include formal Subject line referencing IT Act 2000 and BNS/IPC sections.\n"
                "3. Preserve all concrete facts provided by the victim (dates, amounts, UPI IDs, UTR/txn references, URLs, phone numbers, apps).\n"
                "4. Structure with clear sections: Statement of Facts, Particulars of Digital Evidence & Fraud, Relevant Legal Provisions (IT Act 66C/66D/66E/67, BNS 318(4) / IPC 420), Prayers/Relief Requested (FIR, 1930 freezing, preservation of logs), and Complainant Verification Signature Block.\n"
                "5. Do NOT hallucinate false names or IDs. Use clear bracketed placeholders like [YOUR FULL NAME] or [PLEASE SPECIFY BANK NAME] for details that must be provided by the victim.\n"
                "6. Return ONLY the complaint text without markdown fences, conversational greetings, or notes."
            )
            prompt = (
                f"Incident Category: {incident_type or 'Cyber Crime'}\n"
                f"State / Region: {user_state or 'India'}\n"
                f"Extracted Entities: {json.dumps(entities)}\n\n"
                f"Victim Incident Description:\n{desc}\n\n"
                f"Generate the complete formal cyber complaint draft:"
            )

            fallback_models = ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"]
            for model_name in fallback_models:
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(
                            lambda m=model_name: client.models.generate_content(
                                model=m,
                                contents=f"{system_instruction}\n\n{prompt}",
                            )
                        )
                        result = future.result(timeout=25)
                    text = getattr(result, "text", None)
                    if text and len(text.strip()) > 80:
                        return {
                            "success": True,
                            "draft": text.strip(),
                            "source": "gemini",
                            "extractedEntities": entities,
                        }
                except Exception as inner_exc:
                    logger.warning("[COMPLAINT] Model %s failed: %s", model_name, inner_exc)
                    continue
        except Exception as exc:
            logger.warning("[COMPLAINT] Gemini generation failed: %s; falling back to deterministic template", exc)

    fallback_draft = _generate_fallback_complaint(desc, incident_type, user_state, entities)
    return {
        "success": True,
        "draft": fallback_draft,
        "source": "fallback",
        "extractedEntities": entities,
    }
