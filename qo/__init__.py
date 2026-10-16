"""QO-75: PQC-ready quantum systems orchestrator (stdlib only)."""
__version__ = "0.1.0-quantum"

from .core.bus import EventBus
from .core.telemetry import QuantumTelemetryEngine
from .swarm.agents import AgentSwarm
from .swarm.optimizer import DynamicResourceOptimizer
from .swarm.remediation import AutoRemediation
from .selfheal.supervisor import SelfHealingSupervisor, AutoUpdater

__all__ = [
    "__version__",
    "EventBus",
    "QuantumTelemetryEngine",
    "AgentSwarm",
    "DynamicResourceOptimizer",
    "AutoRemediation",
    "SelfHealingSupervisor",
    "AutoUpdater",
]
