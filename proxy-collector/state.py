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
    fail_count: int = 0
    retired_at: int = 0

    def to_dict(self) -> dict:
        return {
            "last_id": self.last_id,
            "status": self.status,
            "last_ok": self.last_ok,
            "fail_count": self.fail_count,
            "retired_at": self.retired_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChannelState":
        return cls(
            last_id=int(data.get("last_id", 0)),
            status=str(data.get("status", STATUS_ACTIVE)),
            last_ok=str(data.get("last_ok", "")),
            fail_count=int(data.get("fail_count", 0)),
            retired_at=int(data.get("retired_at", 0)),
        )


@dataclass
class State:
    channels: dict[str, ChannelState] = field(default_factory=dict)
    version: int = 1
    updated: str = ""
    run_count: int = 0


def _prefer(a: ChannelState, b: ChannelState) -> ChannelState:
    """Pick the more informative of two records for the same channel name."""
    if a.last_id != b.last_id:
        return a if a.last_id > b.last_id else b
    a_active = a.status == STATUS_ACTIVE
    b_active = b.status == STATUS_ACTIVE
    if a_active != b_active:
        return a if a_active else b
    return a if a.fail_count <= b.fail_count else b


def load_state(path: str) -> State:
    if not path or not os.path.exists(path):
        return State()
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            return State()
        raw_channels = raw.get("channels") or {}
        if not isinstance(raw_channels, dict):
            return State()
        channels: dict[str, ChannelState] = {}
        for name, data in raw_channels.items():
            try:
                parsed = ChannelState.from_dict(data)
            except (TypeError, ValueError, AttributeError):
                continue
            key = name.lower()
            existing = channels.get(key)
            channels[key] = parsed if existing is None else _prefer(existing, parsed)
        return State(
            channels=channels,
            version=int(raw.get("version", 1)),
            updated=str(raw.get("updated", "")),
            run_count=int(raw.get("run_count", 0)),
        )
    except (OSError, ValueError, TypeError):
        return State()


def save_state(path: str, state: State) -> None:
    data = {
        "version": state.version,
        "updated": state.updated,
        "run_count": state.run_count,
        "channels": {name: cs.to_dict() for name, cs in sorted(state.channels.items())},
    }
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def apply_run(
    base: State,
    updates: dict[str, ChannelState],
    retire_after: int,
    retry_after: int,
) -> State:
    channels = dict(base.channels)
    run_count = base.run_count + 1
    for name, update in updates.items():
        existing = channels.get(name, ChannelState())
        if update.status == STATUS_INVALID:
            fail_count = existing.fail_count + 1
            retired_at = existing.retired_at
            if retire_after > 0 and fail_count >= retire_after:
                retired_at = run_count
            channels[name] = ChannelState(
                last_id=max(existing.last_id, update.last_id),
                status=STATUS_INVALID,
                last_ok=existing.last_ok,
                fail_count=fail_count,
                retired_at=retired_at,
            )
        else:
            channels[name] = ChannelState(
                last_id=max(existing.last_id, update.last_id),
                status=update.status,
                last_ok=update.last_ok or existing.last_ok,
                fail_count=0,
                retired_at=0,
            )
    return State(channels=channels, version=base.version, updated=base.updated, run_count=run_count)


def is_due(state: State, name: str, retry_after: int) -> bool:
    channel = state.channels.get(name)
    if channel is None or channel.retired_at == 0:
        return True
    if retry_after <= 0:
        return True
    return state.run_count - channel.retired_at >= retry_after


def select_channels(seed: list[str], state: State, retry_after: int) -> list[str]:
    names = {c.lower() for c in seed} | {c.lower() for c in state.channels}
    return sorted(name for name in names if is_due(state, name, retry_after))
