"""Evidence-grounded RAG + LLM analysis (Stage 12).

Retrieves stored evidence, grounds an LLM on it, and returns structured
analysis whose factual claims must cite retrievable sources. Stage 6 remains
authoritative and the LLM never triggers an automatic block/alert.
"""

from risk_radar.rag.service import (
    RAGAnalysis,
    RAGAnalysisEngine,
    RAGRequest,
)

__all__ = ["RAGAnalysis", "RAGAnalysisEngine", "RAGRequest"]
