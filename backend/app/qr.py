"""Decode a QR code from an uploaded image. The decoded text is only ever treated as a URL to assess."""
from __future__ import annotations

import io

import zxingcpp
from PIL import Image, UnidentifiedImageError

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 20_000_000
ALLOWED_FORMATS = frozenset({"PNG", "JPEG", "WEBP", "GIF", "BMP"})


class QrError(ValueError):
    """The upload isn't a usable QR image. The message is safe to show to the user."""


def decode_qr(data: bytes) -> str:
    if len(data) > MAX_BYTES:
        raise QrError("Image is larger than 5 MB.")
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # Pillow raises DecompressionBombError past 2x this
    try:
        img = Image.open(io.BytesIO(data))
        if img.format not in ALLOWED_FORMATS:
            raise QrError("Upload a PNG, JPEG, WebP, GIF or BMP image.")
        if img.width * img.height > MAX_PIXELS:
            raise QrError("Image has too many pixels.")
        img.load()
        img = img.convert("RGB")
    except QrError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        raise QrError("Could not read this file as an image.") from None
    codes = [c for c in zxingcpp.read_barcodes(img) if c.format == zxingcpp.BarcodeFormat.QRCode and c.text]
    if not codes:
        raise QrError("No QR code found in this image.")
    return codes[0].text.strip()
