"""
QR Code Decoder
===============
Decodes QR codes from uploaded images using multiple strategies:
1. pyzbar (fast, very accurate for clean images)
2. OpenCV QRCodeDetector (fallback for rotated/small QRs)
3. Preprocessing pipeline (grayscale, resize, denoise) for difficult images
"""
import io
import cv2
import numpy as np
from PIL import Image

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


def _preprocess_image(img_bgr: np.ndarray) -> list:
    """
    Return a list of preprocessed image variants to try decoding.
    More variants = better chances of decoding difficult QR codes.
    """
    variants = [img_bgr]
    gray     = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

    # Upscale small images — QR detectors need at least ~200x200px
    h, w = gray.shape
    if max(h, w) < 600:
        scale = 600 / max(h, w)
        gray  = cv2.resize(gray, (int(w*scale), int(h*scale)), interpolation=cv2.INTER_CUBIC)

    variants.append(gray)

    # Adaptive threshold — helps with uneven lighting
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    variants.append(thresh)

    # Denoised version
    denoised = cv2.fastNlMeansDenoising(gray, h=10)
    variants.append(denoised)

    # Sharpened
    kernel    = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
    sharpened = cv2.filter2D(gray, -1, kernel)
    variants.append(sharpened)

    return variants


def decode_qr(file_bytes: bytes) -> dict:
    """
    Decode a QR code from image bytes.

    Returns:
        {
          'success': bool,
          'data': str or None,    # decoded text/URL
          'method': str,          # which decoder succeeded
          'error': str or None,
        }
    """
    result = {'success': False, 'data': None, 'method': None, 'error': None}

    try:
        # Load image with PIL (handles many formats: PNG, JPEG, BMP, WebP...)
        pil_img = Image.open(io.BytesIO(file_bytes)).convert('RGB')
        img_np  = np.array(pil_img)
        img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
    except Exception as e:
        result['error'] = f'Could not open image: {e}'
        return result

    # Try pyzbar first — fastest and most accurate
    if PYZBAR_AVAILABLE:
        try:
            gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
            barcodes = pyzbar.decode(gray)
            if barcodes:
                data = barcodes[0].data.decode('utf-8', errors='replace')
                result.update({'success': True, 'data': data, 'method': 'pyzbar'})
                return result

            # Try with preprocessing if initial attempt failed
            for variant in _preprocess_image(img_bgr):
                barcodes = pyzbar.decode(variant)
                if barcodes:
                    data = barcodes[0].data.decode('utf-8', errors='replace')
                    result.update({'success': True, 'data': data, 'method': 'pyzbar+preprocess'})
                    return result
        except Exception:
            pass  # Fall through to OpenCV

    # Fallback: OpenCV QRCodeDetector
    detector = cv2.QRCodeDetector()
    for variant in _preprocess_image(img_bgr):
        try:
            data, _, _ = detector.detectAndDecode(variant)
            if data:
                result.update({'success': True, 'data': data, 'method': 'opencv'})
                return result
        except Exception:
            continue

    result['error'] = (
        'No QR code detected. Ensure the image is clear, well-lit, '
        'and the QR code is fully visible without obstruction.'
    )
    return result
