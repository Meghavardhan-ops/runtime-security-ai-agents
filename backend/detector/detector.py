"""Public threat detector interface."""

from backend.detector.classifiers import Detector, detect
from backend.detector.models import DetectionResult

__all__ = ["DetectionResult", "Detector", "detect"]

