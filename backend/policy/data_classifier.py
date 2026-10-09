"""Safe interface placeholder for future data classification."""

from typing import Literal

from pydantic import BaseModel


class DataClassification(BaseModel):
    """Caller-provided classification context that is not independently verified."""

    data_type: str
    destination: str
    status: Literal["not_implemented"] = "not_implemented"


class DataClassifier:
    """Carry supplied labels without claiming to classify the underlying data."""

    @property
    def is_available(self) -> bool:
        """This placeholder does not provide trusted content classification."""
        return False

    def classify(self, data_type: str, destination: str) -> DataClassification:
        """Mark caller-provided labels as unverified classification context."""
        return DataClassification(data_type=data_type, destination=destination)
