from dataclasses import dataclass, field
from typing import Protocol

from state import ChannelState


@dataclass
class FetchResult:
    configs: list[str] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    state_updates: dict[str, ChannelState] = field(default_factory=dict)


class SourceAdapter(Protocol):
    def fetch(self) -> FetchResult: ...
