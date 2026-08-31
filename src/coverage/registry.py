from dataclasses import dataclass
from typing import Pattern, Protocol


@dataclass(frozen=True)
class UnsupportedCommandFamily:
    family_id: str
    pattern: Pattern[str]
    rationale: str


class CoverageRegistry(Protocol):
    def match_unsupported_family(
        self,
        command: str,
    ) -> UnsupportedCommandFamily | None: ...

    def is_out_of_scope(self, command: str) -> bool: ...


def default_coverage_registry() -> CoverageRegistry:
    """Return the Cisco registry for V1 direct-service compatibility only."""
    from src.coverage.cisco_registry import CiscoCoverageRegistry

    return CiscoCoverageRegistry()
