"""Shared result types so SMTP and IMAP probes print and serialise the same way."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import Diagnosis


@dataclass
class Step:
    label: str
    sent: str | None
    code: int | None
    reply: list[str]
    elapsed_ms: float
    ok: bool = True
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "sent": self.sent,
            "code": self.code,
            "reply": list(self.reply),
            "elapsed_ms": round(self.elapsed_ms, 1),
            "ok": self.ok,
            "note": self.note,
        }


@dataclass
class ProbeResult:
    protocol: str
    host: str
    port: int
    mode: str
    steps: list[Step] = field(default_factory=list)
    ok: bool = True
    failed_at: str | None = None
    diagnosis: Diagnosis | None = None
    tls_version: str | None = None
    capabilities: list[str] = field(default_factory=list)

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    def fail(self, label: str, diagnosis: Diagnosis, note: str | None = None) -> None:
        self.ok = False
        self.failed_at = label
        self.diagnosis = diagnosis
        if note:
            self.steps.append(Step(label, None, None, [], 0.0, ok=False, note=note))

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "mode": self.mode,
            "ok": self.ok,
            "failed_at": self.failed_at,
            "tls_version": self.tls_version,
            "capabilities": list(self.capabilities),
            "steps": [s.to_dict() for s in self.steps],
            "diagnosis": self.diagnosis.to_dict() if self.diagnosis else None,
        }

    def to_text(self) -> str:
        out = [f"{self.protocol.upper()} probe {self.host}:{self.port} ({self.mode})", ""]
        for step in self.steps:
            tag = "ok  " if step.ok else "FAIL"
            out.append(f"[{tag}] {step.label} ({step.elapsed_ms:.0f} ms)")
            if step.sent:
                out.append(f"       C: {step.sent}")
            for line in step.reply:
                out.append(f"       S: {line}")
            if step.note:
                out.append(f"       ! {step.note}")
        out.append("")
        if self.ok:
            tls = f", {self.tls_version}" if self.tls_version else ""
            out.append(f"Result: all checks passed{tls}")
            return "\n".join(out)
        out.append(f"Result: failed at '{self.failed_at}'")
        if self.diagnosis:
            d = self.diagnosis
            head = d.summary
            if d.code:
                head += f" [{d.code}" + (f" {d.enhanced}" if d.enhanced else "") + "]"
            out.append(f"Category: {d.category}")
            out.append(f"Diagnosis: {head}")
            if d.likely_causes:
                out.append("Likely causes:")
                out.extend(f"  - {c}" for c in d.likely_causes)
            if d.next_steps:
                out.append("Next steps:")
                out.extend(f"  - {s}" for s in d.next_steps)
        return "\n".join(out)
