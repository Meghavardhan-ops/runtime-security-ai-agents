"""Bounded raster image validation and local OCR for untrusted uploads."""

from __future__ import annotations

import warnings
from io import BytesIO
from pathlib import Path
import shutil

from PIL import Image, UnidentifiedImageError
import pytesseract

from backend.core.config import settings

WINDOWS_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
SUPPORTED_IMAGE_FORMATS = frozenset({"PNG", "JPEG"})


class ImageUploadTooLargeError(ValueError):
    """The encoded image or decoded dimensions exceed configured limits."""


class UnsupportedImageFormatError(ValueError):
    """The decoded image format is not an accepted raster format."""


class InvalidImageError(ValueError):
    """The upload is not a valid, fully decodable supported image."""


class OCREngineUnavailableError(RuntimeError):
    """No configured or discoverable Tesseract executable is available."""


class ImageOCRError(RuntimeError):
    """Tesseract failed while processing a validated image."""


class ImageGateway:
    """Validate bounded image bytes and extract text without persisting uploads."""

    def __init__(
        self,
        max_upload_bytes: int | None = None,
        max_pixels: int | None = None,
        tesseract_cmd: str | None = None,
    ) -> None:
        self.max_upload_bytes = (
            settings.image_max_upload_bytes
            if max_upload_bytes is None
            else max_upload_bytes
        )
        self.max_pixels = (
            settings.image_max_pixels if max_pixels is None else max_pixels
        )
        self.tesseract_cmd = (
            settings.tesseract_cmd if tesseract_cmd is None else tesseract_cmd
        ).strip()
        if min(self.max_upload_bytes, self.max_pixels) <= 0:
            raise ValueError("Image upload and pixel limits must be positive")

    def extract_text(self, image_bytes: bytes) -> str:
        """Decode the image, then return trimmed OCR text without logging it."""
        image = self._decode(image_bytes)
        try:
            executable = self._resolve_tesseract_executable()
            if executable is None:
                raise OCREngineUnavailableError
            pytesseract.pytesseract.tesseract_cmd = executable
            text = pytesseract.image_to_string(image)
        except OCREngineUnavailableError:
            raise
        except pytesseract.TesseractNotFoundError:
            raise OCREngineUnavailableError from None
        except Exception:
            # OCR exceptions may contain command details; return no engine output.
            raise ImageOCRError from None
        finally:
            image.close()

        if not isinstance(text, str):
            return ""
        usable_text = text.strip()
        if not any(
            character.isprintable() and not character.isspace()
            for character in usable_text
        ):
            return ""
        return usable_text

    def _decode(self, image_bytes: bytes) -> Image.Image:
        if not isinstance(image_bytes, bytes) or not image_bytes:
            raise InvalidImageError from None
        if len(image_bytes) > self.max_upload_bytes:
            raise ImageUploadTooLargeError from None

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(image_bytes)) as image:
                    if image.format not in SUPPORTED_IMAGE_FORMATS:
                        raise UnsupportedImageFormatError
                    width, height = image.size
                    if width <= 0 or height <= 0:
                        raise InvalidImageError
                    if width * height > self.max_pixels:
                        raise ImageUploadTooLargeError
                    # Force actual pixel decoding before OCR accepts the image.
                    image.load()
                    return image.convert("RGB")
        except (
            UnsupportedImageFormatError,
            ImageUploadTooLargeError,
            InvalidImageError,
        ):
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning):
            raise ImageUploadTooLargeError from None
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
            raise InvalidImageError from None

    def _resolve_tesseract_executable(self) -> str | None:
        if self.tesseract_cmd:
            if Path(self.tesseract_cmd).is_file() or shutil.which(self.tesseract_cmd):
                return self.tesseract_cmd
            return None

        if Path(WINDOWS_TESSERACT_PATH).is_file():
            return WINDOWS_TESSERACT_PATH
        return shutil.which("tesseract")
