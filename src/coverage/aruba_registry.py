import re

from src.coverage.registry import UnsupportedCommandFamily


UNSUPPORTED_COMMAND_FAMILIES = (
    UnsupportedCommandFamily(
        family_id="arp_inspection_trust",
        pattern=re.compile(r"^(?:no )?arp inspection trust$"),
        rationale="Unsupported AOS-CX DAI interface trust state.",
    ),
)

OUT_OF_SCOPE_PATTERNS = (re.compile(r"^(?:exit|end)$"),)


class ArubaCoverageRegistry:
    @staticmethod
    def match_unsupported_family(
        command: str,
    ) -> UnsupportedCommandFamily | None:
        return next(
            (
                family
                for family in UNSUPPORTED_COMMAND_FAMILIES
                if family.pattern.fullmatch(command)
            ),
            None,
        )

    @staticmethod
    def is_out_of_scope(command: str) -> bool:
        return any(
            pattern.fullmatch(command)
            for pattern in OUT_OF_SCOPE_PATTERNS
        )
