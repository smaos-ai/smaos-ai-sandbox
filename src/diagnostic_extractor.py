"""
GLiNER2 Diagnostic Log Extractor (Advisory Enrichment Plane).
Parses heterogeneous provider error text into structured cause categories.
"""
from gliner2 import AutoExtractor

# Verified model checkpoint reference
CHECKPOINT_ID = "fastino/GLiNER2.5-Decide"

def load_diagnostic_extractor():
    """Loads pre-trained extractor for non-authoritative log tagging."""
    return AutoExtractor.from_pretrained(CHECKPOINT_ID)

def extract_error_cause(extractor, raw_error_text: str, labels: list[str]) -> dict:
    """
    Extracts candidate root-cause tags from unstructured provider error text.
    NOTE: Output is strictly advisory and CANNOT alter the deterministic wire state.
    """
    return extractor.extract(raw_error_text, labels=labels)
