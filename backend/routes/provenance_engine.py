"""
Provenance and Container Forensics Engine for Veyron.
Inspects original file bytes directly for:
- SHA-256 hash
- Container structures (JPEG APP markers / DQT, PNG text chunks / C2PA boxes, WebP RIFF)
- Standard EXIF & SubIFD tags (Make, Model, Lens, Exposure, DateTimeOriginal, Software, etc.)
- XMP metadata (DigitalSourceType, CreatorTool, Workflow)
- C2PA / Coalition for Content Provenance and Authenticity (using c2pa-python)
- Google AI / SynthID provenance markers
- Multi-factor provenance scoring:
  * camera_provenance_score
  * ai_provenance_score
  * metadata_integrity_score
  * credential_validity_score
  * provenance_conflict_score
"""

import os
import re
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from PIL import Image, ExifTags

logger = logging.getLogger("veyron.provenance")

# Optional c2pa library
try:
    import c2pa
    C2PA_AVAILABLE = True
except ImportError:
    c2pa = None
    C2PA_AVAILABLE = False
    logger.warning("[Provenance] c2pa-python not installed; C2PA parsing disabled.")

KNOWN_AI_SOFTWARE_PATTERNS = re.compile(
    r"midjourney|dall[·-]?e|stable.?diffusion|sdxl|flux(?:\.1|-dev|-schnell)?|"
    r"c2pa|trainedalgorithmicmedia|adobe.?firefly|firefly|bing.?image|"
    r"microsoft.?designer|comfyui|novelai|automatic1111|invokeai|leonardo\.?ai|"
    r"ideogram|recraft|nightcafe|playground\.?ai|openai|synthid|imagen|"
    r"steps:\s*\d+,\s*sampler:|negative_prompt:|generative.?fill|ai.?generated",
    re.IGNORECASE
)

CAMERA_MANUFACTURERS = [
    "apple", "samsung", "google", "sony", "canon", "nikon", "xiaomi",
    "oneplus", "oppo", "vivo", "realme", "motorola", "huawei", "honor",
    "fujifilm", "panasonic", "olympus", "leica", "hasselblad", "gopro"
]


class ProvenanceEngine:
    def __init__(self):
        pass

    def compute_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def inspect_container(self, file_path: str) -> Dict[str, Any]:
        """Inspects binary container without altering image."""
        size_bytes = os.path.getsize(file_path)
        ext = Path(file_path).suffix.lower()

        info: Dict[str, Any] = {
            "file_size": size_bytes,
            "format": ext.replace(".", "").upper(),
            "mime_type": f"image/{ext.replace('.', '')}",
            "original_dimensions": [0, 0],
            "jpeg_markers": [],
            "png_chunks": [],
            "webp_chunks": [],
            "dqt_tables": 0,
        }

        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)

            # Check format from magic bytes
            if header.startswith(b"\xff\xd8"):
                info["format"] = "JPEG"
                info["mime_type"] = "image/jpeg"
                info["jpeg_markers"] = self._parse_jpeg_markers(file_path)
            elif header.startswith(b"\x89PNG\r\n\x1a\n"):
                info["format"] = "PNG"
                info["mime_type"] = "image/png"
                info["png_chunks"] = self._parse_png_chunks(file_path)
            elif header.startswith(b"RIFF") and header[8:12] == b"WEBP":
                info["format"] = "WEBP"
                info["mime_type"] = "image/webp"

            # Dimensions from PIL without loading pixels
            with Image.open(file_path) as im:
                info["original_dimensions"] = [im.width, im.height]
                if not info.get("format"):
                    info["format"] = im.format
        except Exception as exc:
            logger.debug(f"[Provenance] Container inspection error: {exc}")

        return info

    def _parse_jpeg_markers(self, path: str) -> List[str]:
        markers = []
        try:
            with open(path, "rb") as f:
                data = f.read(65536)
            i = 0
            while i < len(data) - 1:
                if data[i] == 0xFF:
                    m = data[i+1]
                    if m == 0xD8: markers.append("SOI")
                    elif m == 0xE0: markers.append("APP0_JFIF")
                    elif m == 0xE1: markers.append("APP1_EXIF_XMP")
                    elif m == 0xE2: markers.append("APP2_ICC_C2PA")
                    elif m == 0xED: markers.append("APP13_IPTC")
                    elif m == 0xDB: markers.append("DQT")
                    elif m == 0xC0: markers.append("SOF0")
                    elif m == 0xC2: markers.append("SOF2")
                    elif m == 0xDA: markers.append("SOS")
                i += 1
        except Exception:
            pass
        return list(dict.fromkeys(markers))

    def _parse_png_chunks(self, path: str) -> List[str]:
        chunks = []
        try:
            with open(path, "rb") as f:
                f.seek(8) # skip PNG signature
                while True:
                    length_bytes = f.read(4)
                    if len(length_bytes) < 4: break
                    length = int.from_bytes(length_bytes, "big")
                    chunk_type = f.read(4).decode("latin-1", errors="ignore")
                    chunks.append(chunk_type)
                    f.seek(length + 4, 1) # skip data + CRC
                    if chunk_type == "IEND" or len(chunks) > 50: break
        except Exception:
            pass
        return list(dict.fromkeys(chunks))

    def extract_exif(self, file_path: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Extracts standard EXIF and SubIFDs tags."""
        raw_tags: Dict[str, Any] = {}
        parsed_fields: Dict[str, str] = {}

        try:
            with Image.open(file_path) as im:
                exif = im.getexif()
                if exif:
                    for k, v in exif.items():
                        name = ExifTags.TAGS.get(k, str(k))
                        raw_tags[name] = v
                        parsed_fields[name] = str(v)[:200]

                    # SubIFDs
                    for ifd_id in (ExifTags.IFD.Exif, ExifTags.IFD.GPSInfo):
                        try:
                            sub = exif.get_ifd(ifd_id)
                            for sk, sv in sub.items():
                                name = ExifTags.TAGS.get(sk, str(sk))
                                raw_tags[name] = sv
                                parsed_fields[name] = str(sv)[:200]
                        except Exception:
                            pass
        except Exception as exc:
            logger.debug(f"[Provenance] EXIF parsing error: {exc}")

        return raw_tags, parsed_fields

    def extract_xmp(self, file_path: str) -> Dict[str, Any]:
        """Extracts XMP metadata if present."""
        xmp_dict: Dict[str, Any] = {}
        try:
            with Image.open(file_path) as im:
                if hasattr(im, "getxmp"):
                    xmp = im.getxmp()
                    if isinstance(xmp, dict):
                        xmp_dict = xmp
        except Exception as exc:
            logger.debug(f"[Provenance] XMP parsing error: {exc}")
        return xmp_dict

    def extract_png_text_chunks(self, file_path: str) -> Dict[str, str]:
        """Extracts PNG / WebP info dictionary keys."""
        text_info: Dict[str, str] = {}
        try:
            with Image.open(file_path) as im:
                for k, v in im.info.items():
                    if isinstance(v, (str, bytes)):
                        text_info[k] = str(v)[:500]
        except Exception:
            pass
        return text_info

    def inspect_c2pa(self, file_path: str) -> Dict[str, Any]:
        """Uses official c2pa-python library to parse Content Credentials."""
        c2pa_data: Dict[str, Any] = {
            "available": C2PA_AVAILABLE,
            "detected": False,
            "status": "unavailable" if not C2PA_AVAILABLE else "not_present",
            "is_valid": False,
            "claim_generator": None,
            "is_generative_ai": False,
            "is_camera_capture": False,
            "actions": [],
            "validation_state": None,
            "raw_manifest_summary": None,
        }

        if not C2PA_AVAILABLE:
            return c2pa_data

        try:
            reader = c2pa.Reader.try_create(file_path)
            if reader is not None:
                c2pa_data["detected"] = True
                c2pa_data["is_valid"] = reader.is_valid()
                c2pa_data["status"] = "valid" if reader.is_valid() else "invalid_or_untrusted"
                
                manifest_json_str = reader.json()
                manifest = json.loads(manifest_json_str) if manifest_json_str else {}
                c2pa_data["raw_manifest_summary"] = manifest_json_str[:1000]

                active_manifest = manifest.get("active_manifest", {})
                claim_gen = active_manifest.get("claim_generator") or manifest.get("claim_generator")
                c2pa_data["claim_generator"] = claim_gen

                # Check assertions for digitalSourceType
                assertions = active_manifest.get("assertions", [])
                for a in assertions:
                    label = a.get("label", "")
                    data = a.get("data", {})
                    if "c2pa.actions" in label:
                        actions = data.get("actions", [])
                        for act in actions:
                            action_name = act.get("action", "")
                            c2pa_data["actions"].append(action_name)
                            ds_type = act.get("digitalSourceType", "")
                            if "trainedalgorithmicmedia" in ds_type.lower() or "compositeSynthetic" in ds_type:
                                c2pa_data["is_generative_ai"] = True
                            if "c2pa.created" in action_name and ("ai" in str(claim_gen).lower() or "generator" in str(claim_gen).lower()):
                                c2pa_data["is_generative_ai"] = True
                            if "c2pa.captured" in action_name:
                                c2pa_data["is_camera_capture"] = True

                # Check claim generator string
                if claim_gen and KNOWN_AI_SOFTWARE_PATTERNS.search(claim_gen):
                    c2pa_data["is_generative_ai"] = True

                c2pa_data["validation_state"] = str(reader.get_validation_state())
        except Exception as exc:
            logger.debug(f"[Provenance] C2PA read error: {exc}")
            c2pa_data["status"] = f"error: {exc}"

        return c2pa_data

    def inspect_google_provenance(self, file_path: str, c2pa_info: Dict[str, Any], xmp_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects Google AI / SynthID provenance markers.
        SynthID image watermarking is an imperceptible neural watermark created by Google DeepMind.
        Google does not provide a public local standalone verification API for SynthID images.
        Google does embed Content Credentials (C2PA) and XMP metadata in Gemini/Search exports.
        """
        google_detected = False
        match_source = []

        # 1. Check C2PA claim generator
        if c2pa_info.get("detected"):
            cg = str(c2pa_info.get("claim_generator", "")).lower()
            if "google" in cg or "gemini" in cg or "imagen" in cg:
                google_detected = True
                match_source.append(f"C2PA ClaimGenerator: {c2pa_info.get('claim_generator')}")

        # 2. Check XMP metadata
        xmp_str = json.dumps(xmp_info).lower()
        if "google" in xmp_str and ("synthid" in xmp_str or "gemini" in xmp_str or "imagen" in xmp_str or "trainedalgorithmicmedia" in xmp_str):
            google_detected = True
            match_source.append("XMP metadata indicates Google Generative AI")

        # 3. Check binary headers for Google markers
        try:
            with open(file_path, "rb") as f:
                header = f.read(65536).decode("latin-1", errors="ignore")
                if "Google Inc." in header and ("Gemini" in header or "Imagen" in header):
                    google_detected = True
                    match_source.append("File header contains Google AI signatures")
        except Exception:
            pass

        return {
            "google_provenance_detected": google_detected,
            "google_provenance_status": "detected" if google_detected else "not_detected",
            "synthid_verification_api": "unavailable_locally (SynthID imperceptible watermark verification requires proprietary Google Cloud API)",
            "details": " | ".join(match_source) if match_source else "No Google AI provenance signatures found."
        }

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Executes full provenance audit directly on raw file bytes."""
        sha256 = self.compute_sha256(file_path)
        container_info = self.inspect_container(file_path)
        raw_exif, exif_fields = self.extract_exif(file_path)
        xmp_info = self.extract_xmp(file_path)
        png_text = self.extract_png_text_chunks(file_path)
        c2pa_info = self.inspect_c2pa(file_path)
        google_info = self.inspect_google_provenance(file_path, c2pa_info, xmp_info)

        # Identify Camera Hardware
        make = exif_fields.get("Make", "").strip()
        model = exif_fields.get("Model", "").strip()
        lens_make = exif_fields.get("LensMake", "").strip()
        lens_model = exif_fields.get("LensModel", "").strip()
        software_tag = exif_fields.get("Software", "").strip() or png_text.get("Software", "").strip()
        user_comment = exif_fields.get("UserComment", "").strip()
        img_desc = exif_fields.get("ImageDescription", "").strip()
        dt_orig = exif_fields.get("DateTimeOriginal", "").strip() or exif_fields.get("DateTime", "").strip()

        # Optical Exposure Fields
        opt_keys = ["ExposureTime", "FNumber", "ISOSpeedRatings", "PhotographicSensitivity",
                    "FocalLength", "Flash", "WhiteBalance", "MeteringMode"]
        opt_detected = {k: exif_fields[k] for k in opt_keys if k in exif_fields}

        is_recognized_maker = any(m in make.lower() for m in CAMERA_MANUFACTURERS) or (make and model)
        has_optical_exposure = len(opt_detected) >= 2

        # Identify AI Generator signatures
        ai_signals_found = []
        creator_tool = None
        generator_tool = None

        # Check software tag & user comments
        for s in [software_tag, user_comment, img_desc]:
            if s and KNOWN_AI_SOFTWARE_PATTERNS.search(s):
                ai_signals_found.append(f"Software/Tag: {s[:100]}")
                generator_tool = s

        # Check PNG text chunks
        for k, v in png_text.items():
            if KNOWN_AI_SOFTWARE_PATTERNS.search(f"{k}: {v}"):
                ai_signals_found.append(f"PNG Chunk [{k}]: {v[:100]}")
                generator_tool = generator_tool or f"{k}: {v[:50]}"

        # Check XMP
        xmp_str = json.dumps(xmp_info)
        m = KNOWN_AI_SOFTWARE_PATTERNS.search(xmp_str)
        if m:
            ai_signals_found.append(f"XMP match: {m.group(0)}")
            generator_tool = generator_tool or m.group(0)

        # Check C2PA
        if c2pa_info.get("is_generative_ai"):
            ai_signals_found.append(f"C2PA Generative AI manifest ({c2pa_info.get('claim_generator')})")
            generator_tool = generator_tool or c2pa_info.get("claim_generator")

        if google_info.get("google_provenance_detected"):
            ai_signals_found.append(f"Google AI Provenance ({google_info.get('details')})")
            generator_tool = generator_tool or "Google Gemini / Imagen"

        # --- Compute Disaggregated Provenance Scores ---
        # 1. Camera Provenance Score [0.0 - 1.0]
        if c2pa_info.get("is_camera_capture"):
            camera_provenance_score = 0.98
        elif is_recognized_maker and has_optical_exposure and dt_orig:
            camera_provenance_score = 0.92
        elif is_recognized_maker and has_optical_exposure:
            camera_provenance_score = 0.85
        elif make or model:
            camera_provenance_score = 0.40
        else:
            camera_provenance_score = 0.05

        # 2. AI Provenance Score [0.0 - 1.0]
        if c2pa_info.get("is_generative_ai"):
            ai_provenance_score = 0.99
        elif google_info.get("google_provenance_detected"):
            ai_provenance_score = 0.96
        elif len(ai_signals_found) >= 2:
            ai_provenance_score = 0.95
        elif len(ai_signals_found) == 1:
            ai_provenance_score = 0.90
        else:
            ai_provenance_score = 0.02

        # 3. Metadata Integrity Score [0.0 - 1.0]
        # Measures whether container, headers, and metadata are coherent
        integrity_score = 0.50 # default neutral
        if is_recognized_maker and has_optical_exposure:
            integrity_score = 0.90
        elif c2pa_info.get("detected") and c2pa_info.get("is_valid"):
            integrity_score = 0.95
        elif not exif_fields and not xmp_info and not png_text:
            integrity_score = 0.30 # stripped/minimal metadata

        # 4. Credential Validity Score [0.0 - 1.0]
        if c2pa_info.get("detected"):
            cred_score = 1.0 if c2pa_info.get("is_valid") else 0.20
        else:
            cred_score = 0.0 # no credentials present

        # 5. Provenance Conflict Score [0.0 - 1.0]
        # Detects contradiction: camera metadata claims original capture, but C2PA/XMP indicates AI
        conflict_score = 0.0
        if camera_provenance_score > 0.70 and ai_provenance_score > 0.70:
            conflict_score = 0.95
            logger.warning("[Provenance] CONTRADICTION: Both camera and AI signatures present!")
        elif camera_provenance_score > 0.50 and ai_provenance_score > 0.50:
            conflict_score = 0.60

        return {
            "sha256": sha256,
            "container": container_info,
            "exif_tags_count": len(exif_fields),
            "exif_fields": exif_fields,
            "xmp_present": bool(xmp_info),
            "xmp_fields": list(xmp_info.keys()),
            "png_text_chunks": png_text,
            "camera_maker": make or None,
            "camera_model": model or None,
            "lens_make": lens_make or None,
            "lens_model": lens_model or None,
            "software_tag": software_tag or None,
            "creator_tool": creator_tool,
            "generator_tool": generator_tool,
            "optical_exposure_tags": opt_detected,
            "c2pa": c2pa_info,
            "google_provenance": google_info,
            "ai_signatures_found": ai_signals_found,
            "scores": {
                "camera_provenance_score": round(camera_provenance_score, 3),
                "ai_provenance_score": round(ai_provenance_score, 3),
                "metadata_integrity_score": round(integrity_score, 3),
                "credential_validity_score": round(cred_score, 3),
                "provenance_conflict_score": round(conflict_score, 3),
            }
        }
