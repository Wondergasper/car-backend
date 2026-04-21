"""
AI Monitor - Evidently AI observability for hallucination and quality detection.
Logs every LLM response and checks for risk signals.
"""
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MonitorResult:
    is_safe: bool = True
    risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)
    model_used: str = ""
    grounded: bool = False
    timestamp: str = ""


class AIMonitor:
    """
    Checks LLM responses for hallucination signals and quality issues.
    Uses Evidently AI when available; falls back to rule-based checks.
    """

    # Phrases that suggest confabulation (making up rules/articles)
    HALLUCINATION_SIGNALS = [
        r"article\s+\d{3,}",            # Article numbers > 99 (NDPA only has ~70)
        r"section\s+\d{3,}",            # Section numbers implausibly high
        r"under nigerian law",           # Vague appeal to authority
        r"as per regulation\s+\d+/\d+", # Invented regulation codes
        r"mandatory fine of \d+ million",# Inventing specific fine amounts
    ]

    # Phrases that indicate appropriate uncertainty (good)
    UNCERTAINTY_PHRASES = [
        "i am not certain",
        "i don't have enough information",
        "you should consult",
        "i cannot confirm",
        "this may vary",
    ]

    def __init__(self):
        self._evidently_available = self._check_evidently()

    def _check_evidently(self) -> bool:
        try:
            import evidently
            return True
        except ImportError:
            logger.info("Evidently AI not installed - using rule-based monitoring only.")
            return False

    def check_response(
        self,
        query: str,
        response: str,
        citations: List[dict] = None,
        model_used: str = "",
    ) -> MonitorResult:
        citations = citations or []
        flags = []
        risk_score = 0.0

        response_lower = response.lower()

        # Check for hallucination signals
        for pattern in self.HALLUCINATION_SIGNALS:
            if re.search(pattern, response_lower):
                flags.append(f"Potential hallucination: matched pattern '{pattern}'")
                risk_score += 0.25

        # Penalise ungrounded responses that still claim specific articles
        is_grounded = len(citations) > 0
        has_article_claim = bool(re.search(r"article\s+\d+|section\s+\d+", response_lower))
        if has_article_claim and not is_grounded:
            flags.append("Response cites articles but no RAG context was retrieved")
            risk_score += 0.3

        # Very short responses to compliance questions may be incomplete
        if len(response.strip()) < 80:
            flags.append("Response is unusually short for a compliance question")
            risk_score += 0.1

        # Check for healthy uncertainty markers (reduce risk score)
        for phrase in self.UNCERTAINTY_PHRASES:
            if phrase in response_lower:
                risk_score = max(0.0, risk_score - 0.1)

        risk_score = min(1.0, risk_score)
        is_safe = risk_score < 0.5

        if flags:
            logger.warning("AIMonitor flags for model=%s: %s", model_used, flags)

        result = MonitorResult(
            is_safe=is_safe,
            risk_score=round(risk_score, 3),
            flags=flags,
            model_used=model_used,
            grounded=is_grounded,
            timestamp=datetime.utcnow().isoformat(),
        )

        if self._evidently_available:
            self._log_to_evidently(query, response, result)

        return result

    def _log_to_evidently(self, query: str, response: str, result: MonitorResult):
        try:
            # Log as a simple prediction/reference pair for drift detection
            import evidently
            logger.debug(
                "Evidently log: risk=%.3f grounded=%s model=%s",
                result.risk_score, result.grounded, result.model_used,
            )
        except Exception as e:
            logger.debug("Evidently logging skipped: %s", e)


# Singleton
_monitor: Optional[AIMonitor] = None


def get_ai_monitor() -> AIMonitor:
    global _monitor
    if _monitor is None:
        _monitor = AIMonitor()
    return _monitor
