"""maillab: SMTP/IMAP troubleshooting toolkit with a fault-injecting mock server."""

from .errors import Diagnosis, classify, classify_network
from .imap import ImapProbe
from .result import ProbeResult, Step
from .smtp import SmtpProbe

__all__ = [
    "Diagnosis",
    "ImapProbe",
    "ProbeResult",
    "SmtpProbe",
    "Step",
    "classify",
    "classify_network",
]
__version__ = "1.0.0"
