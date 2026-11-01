from dataclasses import dataclass, field, asdict

ALLOW, WARN, BLOCK = "allow", "warn", "block"
WARN_AT, BLOCK_AT = 30, 60


@dataclass
class Finding:
    code: str
    weight: int
    reason: str


@dataclass
class Verdict:
    target: str
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def decision(self) -> str:
        if any(f.weight >= BLOCK_AT for f in self.findings) or self.score >= BLOCK_AT:
            return BLOCK
        return WARN if self.score >= WARN_AT else ALLOW

    def to_dict(self) -> dict:
        return {"target": self.target, "decision": self.decision, "score": self.score,
                "findings": [asdict(f) for f in self.findings]}
