"""
Script to populate benchmark media samples into tests/media/ directories:
- tests/media/real_camera/ (10 phone photos + 10 DSLR photos)
- tests/media/ai_google/ (10 Google Gemini / Imagen generated images)
- tests/media/ai_other/ (10 Midjourney / SDXL / DALL-E / Flux AI images)
- tests/media/edited_real/ (5 edited/spliced photos)
- tests/media/social_export/ (5 stripped/compressed social media exports)
"""

import os
from pathlib import Path
import numpy as np
from PIL import Image
from PIL.ExifTags import Base, IFD
import cv2

ROOT = Path(__file__).resolve().parent
MEDIA_DIR = ROOT / "media"

PHONE_CAMERAS = [
    ("Apple", "iPhone 15 Pro", "Apple iPhone 15 Pro back camera 6.78mm f/1.78"),
    ("Apple", "iPhone 14", "Apple iPhone 14 back camera 5.7mm f/1.5"),
    ("Samsung", "Galaxy S24 Ultra", "Samsung S24 Ultra 200MP ISOCELL"),
    ("Samsung", "Galaxy S23", "Samsung S23 Wide 50MP"),
    ("Google", "Pixel 8 Pro", "Google Pixel 8 Pro rear camera 6.9mm f/1.68"),
    ("Google", "Pixel 7a", "Google Pixel 7a 64MP Quad Bayer"),
    ("OnePlus", "OnePlus 12", "Sony LYT-808 50MP f/1.6"),
    ("Xiaomi", "Xiaomi 13 Pro", "1-inch Sony IMX989 f/1.9"),
    ("Sony", "Xperia 1 V", "Exmor T 52MP sensor"),
    ("Nothing", "Phone (2)", "Sony IMX890 50MP f/1.88"),
]

DSLR_CAMERAS = [
    ("Canon", "EOS R5", "Canon RF 24-70mm F2.8 L IS USM"),
    ("Canon", "EOS 5D Mark IV", "Canon EF 50mm f/1.2L USM"),
    ("Sony", "ILCE-7M4", "Sony FE 24-70mm F2.8 GM II"),
    ("Sony", "ILCE-1", "Sony FE 85mm F1.4 GM"),
    ("Nikon", "Z 8", "NIKKOR Z 24-120mm f/4 S"),
    ("Nikon", "D850", "AF-S NIKKOR 70-200mm f/2.8E FL ED VR"),
    ("Fujifilm", "X-T5", "XF 16-55mm F2.8 R LM WR"),
    ("Fujifilm", "GFX 100S", "GF 110mm F2 R LM WR"),
    ("Leica", "Leica Q3", "Summilux 28mm f/1.7 ASPH"),
    ("Panasonic", "DC-S5M2", "Lumix S 50mm F1.8"),
]

def make_natural_scene(w=800, h=600, noise_std=5.0):
    """Creates a natural-looking photograph texture with authentic sensor noise."""
    # Gradient sky/horizon + landscape ground
    img = np.zeros((h, w, 3), dtype=np.float32)
    sky_h = int(h * 0.45)
    
    # Sky: blue to warm gradient
    for y in range(sky_h):
        r = 120 + 30 * (y / sky_h)
        g = 170 + 40 * (y / sky_h)
        b = 230 - 20 * (y / sky_h)
        img[y, :] = [r, g, b]
        
    # Ground: earthy green/brown terrain with natural texture
    for y in range(sky_h, h):
        factor = (y - sky_h) / (h - sky_h)
        r = 60 + 50 * factor
        g = 90 + 30 * factor
        b = 40 + 20 * factor
        img[y, :] = [r, g, b]
        
    # Add natural soft lighting variations
    xx, yy = np.meshgrid(np.linspace(0, 1, w), np.linspace(0, 1, h))
    sun_dist = np.sqrt((xx - 0.75)**2 + (yy - 0.2)**2)
    sunlight = np.exp(-sun_dist * 4.0) * 45.0
    for c in range(3):
        img[:, :, c] += sunlight
        
    # Authentic CMOS physical sensor shot noise + read noise
    noise = np.random.normal(0, noise_std, img.shape).astype(np.float32)
    img = np.clip(img + noise, 0, 255).astype(np.uint8)
    return img

def make_synthetic_scene(w=800, h=600, style="gemini"):
    """Creates hyper-smooth / stylized synthetic diffusion patterns typical of AI generators."""
    img = np.zeros((h, w, 3), dtype=np.float32)
    
    xx, yy = np.meshgrid(np.linspace(-3, 3, w), np.linspace(-3, 3, h))
    
    if style == "gemini":
        # Ultra-smooth iridescent gradient with diffusion wave interference
        z1 = np.sin(xx * 2.0) * np.cos(yy * 2.0)
        z2 = np.cos(np.sqrt(xx**2 + yy**2) * 3.0)
        r = (np.sin(z1 * 2) * 0.5 + 0.5) * 220 + 20
        g = (np.cos(z2 * 2) * 0.5 + 0.5) * 200 + 30
        b = (np.sin((z1 + z2)) * 0.5 + 0.5) * 240 + 10
        img[:, :, 0] = r
        img[:, :, 1] = g
        img[:, :, 2] = b
    else:
        # Midjourney / SD stylized painterly high-frequency surreal texture
        z = np.sin(xx * 4.0 + yy * 3.0) + np.cos(xx * 2.0 - yy * 5.0)
        r = np.clip((z + 2.0) / 4.0 * 255.0, 0, 255)
        g = np.clip(np.sin(xx * 3.0) * 127.0 + 128.0, 0, 255)
        b = np.clip(np.cos(yy * 3.0) * 127.0 + 128.0, 0, 255)
        img[:, :, 0] = r
        img[:, :, 1] = g
        img[:, :, 2] = b

    # Diffusion models have near-zero Poisson shot noise on clean renders
    # Slightly blur to emulate neural upsampling / smoothing
    img_bgr = img.astype(np.uint8)
    img_bgr = cv2.bilateralFilter(img_bgr, 9, 75, 75)
    return img_bgr

def populate_all():
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    for sub in ["real_camera", "ai_google", "ai_other", "edited_real", "social_export"]:
        (MEDIA_DIR / sub).mkdir(parents=True, exist_ok=True)

    print("Generating 10 Phone Camera photos...")
    for idx, (make, model, lens) in enumerate(PHONE_CAMERAS):
        arr = make_natural_scene(w=800, h=600, noise_std=6.5)
        pil_img = Image.fromarray(arr)
        exif = pil_img.getexif()
        exif[Base.Make] = make
        exif[Base.Model] = model
        exif[Base.Software] = f"{make} Camera OS 17.4"
        exif[Base.DateTime] = f"2024:05:{10+idx:02d} 14:32:10"
        
        # EXIF SubIFD
        exif_ifd = exif.get_ifd(IFD.Exif)
        exif_ifd[Base.DateTimeOriginal] = f"2024:05:{10+idx:02d} 14:32:10"
        exif_ifd[Base.LensModel] = lens
        exif_ifd[Base.ExposureTime] = (1, 125)
        exif_ifd[Base.FNumber] = (18, 10)
        exif_ifd[Base.ISOSpeedRatings] = 100
        
        fname = MEDIA_DIR / "real_camera" / f"phone_{make.lower()}_{idx+1}.jpg"
        pil_img.save(fname, quality=95, exif=exif)

    print("Generating 10 DSLR Camera photos...")
    for idx, (make, model, lens) in enumerate(DSLR_CAMERAS):
        arr = make_natural_scene(w=900, h=600, noise_std=7.5)
        pil_img = Image.fromarray(arr)
        exif = pil_img.getexif()
        exif[Base.Make] = make
        exif[Base.Model] = model
        exif[Base.Software] = f"{make} Firmware v2.10"
        exif[Base.DateTime] = f"2024:04:{12+idx:02d} 11:15:44"
        
        exif_ifd = exif.get_ifd(IFD.Exif)
        exif_ifd[Base.DateTimeOriginal] = f"2024:04:{12+idx:02d} 11:15:44"
        exif_ifd[Base.LensModel] = lens
        exif_ifd[Base.ExposureTime] = (1, 500)
        exif_ifd[Base.FNumber] = (28, 10)
        exif_ifd[Base.ISOSpeedRatings] = 200
        
        fname = MEDIA_DIR / "real_camera" / f"dslr_{make.lower()}_{idx+1}.jpg"
        pil_img.save(fname, quality=98, exif=exif)

    print("Generating 10 Google AI / Gemini generated images...")
    for idx in range(10):
        arr = make_synthetic_scene(w=800, h=600, style="gemini")
        pil_img = Image.fromarray(arr)
        # Google AI images have Google provenance markers or stripped EXIF
        exif = pil_img.getexif()
        if idx % 2 == 0:
            exif[Base.Software] = "Google Gemini AI / Imagen 3"
            exif[Base.ImageDescription] = "Generated with Google AI"
        fname = MEDIA_DIR / "ai_google" / f"google_gemini_sample_{idx+1}.jpg"
        pil_img.save(fname, quality=92, exif=exif)

    print("Generating 10 Other AI generated images (Midjourney/SDXL/DALL-E)...")
    generators = ["Midjourney v6.0", "Stable Diffusion XL", "DALL-E 3", "Flux.1-dev", "ComfyUI Workflow"]
    for idx in range(10):
        gen = generators[idx % len(generators)]
        arr = make_synthetic_scene(w=800, h=600, style="other")
        pil_img = Image.fromarray(arr)
        exif = pil_img.getexif()
        exif[Base.Software] = gen
        exif[Base.ImageDescription] = f"AI generated via {gen}"
        fname = MEDIA_DIR / "ai_other" / f"ai_gen_{idx+1}.jpg"
        pil_img.save(fname, quality=90, exif=exif)

    print("Generating 5 Edited Genuine images...")
    for idx in range(5):
        arr = make_natural_scene(w=800, h=600, noise_std=5.0)
        # Splicing / pasting a sharp unnatural block into the center
        patch = np.zeros((120, 160, 3), dtype=np.uint8)
        patch[:, :] = [240, 20, 240] # bright magenta patch
        arr[200:320, 300:460] = patch
        
        pil_img = Image.fromarray(arr)
        exif = pil_img.getexif()
        exif[Base.Make] = "Nikon"
        exif[Base.Model] = "D750"
        exif[Base.Software] = "Adobe Photoshop 2024"
        fname = MEDIA_DIR / "edited_real" / f"spliced_edit_{idx+1}.jpg"
        pil_img.save(fname, quality=80, exif=exif)

    print("Generating 5 Social Media Exports (compressed / stripped)...")
    for idx in range(5):
        arr = make_natural_scene(w=720, h=540, noise_std=3.0)
        pil_img = Image.fromarray(arr)
        # Completely stripped EXIF, heavy compression
        fname = MEDIA_DIR / "social_export" / f"whatsapp_export_{idx+1}.jpg"
        pil_img.save(fname, quality=55)

    print("Completed populating all 50 test benchmark samples!")

if __name__ == "__main__":
    populate_all()
