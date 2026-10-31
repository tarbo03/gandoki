"""The honesty contract.

Every finding MUST be constructible through this module, and to_public_dict()
enforces the contract at export time — no scanner path can bypass it.
The AI write surface is EXACTLY one field: `Finding.section`.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class FindingCategory(str, Enum):
    SECRET = "secret"
    DEBUG_EXPOSURE = "debug_exposure"


class ConfidenceTier(str, Enum):
    # Only the validator subsystem may set VALIDATED_LIVE / CONFIRMED_PARTIAL.
    VALIDATED_LIVE = "VALIDATED_LIVE"
    CONFIRMED_PARTIAL = "CONFIRMED_PARTIAL"
    FORMAT_MATCH = "FORMAT_MATCH"
    SUSPECTED = "SUSPECTED"
    KNOWN_PUBLIC = "KNOWN_PUBLIC"          # internal filter — never exported


class ValidationStatus(str, Enum):
    NOT_TESTED = "NOT_TESTED"
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"                     # only on authenticated 401/403
    INCONCLUSIVE = "INCONCLUSIVE"         # network/rate-limit — NOT "dead"
    DISABLED = "DISABLED"                 # type not opted into live validation
    REFUSED = "REFUSED"                   # destructive validator, auto-fire forbidden


class ImpactLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Section(str, Enum):
    """The AI's ONLY write surface. Everything else is deterministic."""
    ACCEPTED = "ACCEPTED"
    RETRACTED = "RETRACTED"


class Provenance(str, Enum):
    """How the finding was located — always recorded, always displayed."""
    REGEX = "regex"
    AI_RECALL_REGEX_CONFIRMED = "ai_recall_regex_confirmed"
    AI_RECALL_GENERIC_EXTRACTOR = "ai_recall_generic_extractor"


@dataclass
class Evidence:
    source_url: str
    asset_url: str
    asset_sha256: str
    asset_size: int
    byte_offset: int
    matched_pattern: str
    matched_snippet: str                  # raw internal; redacted on export
    context_snippet: str                  # ±100 chars
    discovery_method: str                 # html | js_bundle | sourcemap | probe
    entropy_score: Optional[float] = None
    provenance: Provenance = Provenance.REGEX
    recovered_context: Optional[str] = None      # AI enrichment (sourcemap de-minify)
    context_truncated: bool = False              # AI saw truncated context
    prompt_injection_suspected: bool = False     # injection pattern detected


@dataclass
class ValidationResult:
    status: ValidationStatus = ValidationStatus.NOT_TESTED
    method: str = "none"
    notes: str = ""
    performed_at: Optional[datetime] = None
    side_effect: Optional[str] = None


@dataclass
class Impact:
    level: ImpactLevel
    basis: str
    if_valid_capability: str              # "IF VALID, attacker could ..."
    caveat: str                           # ALWAYS non-empty
    cap_reason: Optional[str] = None      # populated by L5 when a cap applies


@dataclass
class CoverageContext:
    pages_fetched: int
    assets_scanned: int
    assets_failed: int
    sources_queried: list[str]
    skipped: list[str]
    crawl_budget_seconds: int
    crawl_started: datetime
    crawl_ended: datetime
    max_domains_enforced: object = 200    # int | "unlimited"
    robots_ignored: bool = False
    assets_skipped_reason: dict = field(default_factory=dict)
    assets_truncated: int = 0             # dropped by max_assets_per_page


@dataclass
class Retraction:
    reason: str
    decided_by: str                       # e.g. "openrouter:meta-llama/llama-3.3-70b-instruct:free"
    decided_at: datetime
    input_hash: str                       # sha256 of exact JSON the model saw


@dataclass
class AIEnrichment:
    """Additive only. Never touches tier / validation / impact."""
    generated_by: str
    generated_at: datetime
    ai_review_hint: Optional[str] = None
    ai_narration: Optional[str] = None
    cluster_hint_ai: Optional[str] = None
    builder_hint_ai: Optional[str] = None
    source_of_truth_hash: Optional[str] = None


@dataclass
class Finding:
    category: FindingCategory
    secret_type: str
    tier: ConfidenceTier
    evidence: Evidence
    impact: Impact
    coverage: CoverageContext
    remediation: str
    validation: ValidationResult = field(default_factory=ValidationResult)
    framework_hint: Optional[str] = None
    builder_hint: Optional[str] = None
    cluster_id: Optional[str] = None
    # --- AI write surface (Section is the ONLY field AI may touch) ---
    section: Section = Section.ACCEPTED
    retraction: Optional[Retraction] = None
    # --- End AI write surface ---
    enrichment: Optional[AIEnrichment] = None
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_public_dict(self) -> dict:
        # --- HONESTY CONTRACT ENFORCEMENT ---
        if self.tier == ConfidenceTier.KNOWN_PUBLIC:
            raise RuntimeError("KNOWN_PUBLIC findings must never be exported")
        if not self.impact.caveat:
            raise RuntimeError("impact.caveat is mandatory")
        if (self.validation.status == ValidationStatus.CONFIRMED
                and self.validation.performed_at is None):
            raise RuntimeError("CONFIRMED requires performed_at")
        if self.validation.side_effect and not self.validation.notes:
            raise RuntimeError("Side-effect validations must explain themselves in notes")
        if self.section == Section.RETRACTED and self.retraction is None:
            raise RuntimeError("RETRACTED section requires a Retraction record")
        # --- END ENFORCEMENT ---
        d = asdict(self)
        d["tier"] = self.tier.value
        d["category"] = self.category.value
        d["section"] = self.section.value
        d["impact"]["level"] = self.impact.level.value
        d["validation"]["status"] = self.validation.status.value
        d["evidence"]["provenance"] = self.evidence.provenance.value
        d["evidence"]["matched_snippet"] = self._redact(self.evidence.matched_snippet)
        d["evidence"]["context_snippet"] = self._redact(self.evidence.context_snippet)
        d["created_at"] = self.created_at.isoformat()
        if self.retraction:
            d["retraction"]["decided_at"] = self.retraction.decided_at.isoformat()
        if self.enrichment:
            d["enrichment"]["generated_at"] = self.enrichment.generated_at.isoformat()
        return d

    @staticmethod
    def _redact(s: str) -> str:
        """Redact a secret for display.

        Policy: reveal at most 4 chars from each end, and never more than
        ~20% of the string total. Short strings are fully masked to prevent
        accidental exposure of nearly-complete short tokens.

        Identifiability is preserved for real secrets (typically 20+ chars)
        while short false-positives / AI-recall candidates stay safe.
        """
        n = len(s)
        if n <= 8:
            return "*" * n
        reveal = min(4, max(1, n // 10))
        return s[:reveal] + "*" * (n - 2 * reveal) + s[-reveal:]
