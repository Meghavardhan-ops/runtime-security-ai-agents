"""Deterministic threat detection interfaces."""

from backend.detector.detector import Detector, DetectionResult, detect

__all__ = ["Detector", "DetectionResult", "detect"]
