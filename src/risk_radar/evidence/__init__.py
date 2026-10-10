"""Multimodal Evidence Engine (Stage 5).

Analyzers return the teammate-owned ``AnalyzerResult`` v1.0 contract from
``app.schemas.evidence``. Stage 6 remains authoritative over exclusion.
"""

from risk_radar.evidence.service import (
    EvidenceAnalysisResult,
    EvidenceEngine,
    EvidenceRequest,
)

__all__ = ["EvidenceAnalysisResult", "EvidenceEngine", "EvidenceRequest"]
