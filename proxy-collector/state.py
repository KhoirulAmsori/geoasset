import json
import os
from dataclasses import dataclass, field

from util import atomic_write

STATUS_ACTIVE = "active"
STATUS_INVALID = "invalid"


@dataclass
class ChannelState:
    last_id: int = 0
    status: str = STATUS_ACTIVE
    last_ok: str = ""

    def to_dict(self) -> dict:
        return {"last_id": self.last_id, "status": self.status, "last_ok": self.last_ok}

    @classmethod
    def from_dict(cls, data: dict) -> "ChannelState":
        return cls(
            last_id=int(data.get("last_id", 0)),
            status=str(data.get("status", STATUS_ACTIVE)),
            last_ok=str(data.get("last_ok", "")),
        )


@dataclass
class State:
    channels: dict[str, ChannelState] = field(default_factory=dict)
    version: int = 1
    updated: str = ""


def load_state(path: str) -> State:
    if not path or not os.path.exists(path):
        return State()
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return State()
    channels: dict[str, ChannelState] = {}
    for name, data in (raw.get("channels") or {}).items():
        try:
            channels[name] = ChannelState.from_dict(data)
        except (TypeError, ValueError, AttributeError):
            continue
    return State(
        channels=channels,
        version=int(raw.get("version", 1)),
        updated=str(raw.get("updated", "")),
    )


def save_state(path: str, state: State) -> None:
    data = {
        "version": state.version,
        "updated": state.updated,
        "channels": {name: cs.to_dict() for name, cs in sorted(state.channels.items())},
    }
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def merge_state(base: State, updates: dict[str, ChannelState]) -> State:
    channels = dict(base.channels)
    channels.update(updates)
    return State(channels=channels, version=base.version, updated=base.updated)
