from datetime import datetime, timezone
from typing import Callable

from adapters.base import SourceAdapter
from config import Config
from extract import dedupe_sorted
from state import apply_run, load_state, save_state
from util import atomic_write


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_collection(
    cfg: Config,
    adapters: list[SourceAdapter],
    log: Callable[[str], None] | None = None,
) -> int:
    log = log or (lambda _msg: None)

    state = load_state(cfg.channels_state_file)

    all_configs: list[str] = []
    updates = {}
    errors: list[str] = []
    adapter_count = 0
    failed_adapters = 0

    for adapter in adapters:
        adapter_count += 1
        result = adapter.fetch()
        all_configs.extend(result.configs)
        updates.update(result.state_updates)
        errors.extend(result.errors)
        if result.errors and not result.configs:
            failed_adapters += 1

    for err in errors:
        log(f"error: {err}")

    state = apply_run(state, updates, cfg.retire_after, cfg.retry_after)
    state.updated = _now_iso()

    configs = dedupe_sorted(all_configs)
    body = "\n".join(configs)
    if body:
        body += "\n"
    atomic_write(cfg.collected_file, body)
    save_state(cfg.channels_state_file, state)
    log(f"collected {len(configs)} configs from {adapter_count} adapters")

    if cfg.min_collected > 0 and len(configs) < cfg.min_collected:
        log(f"collected ({len(configs)}) below minimum ({cfg.min_collected}), writing skip flag")
        atomic_write(cfg.skip_push_flag, "not enough collected configs\n")

    if not configs and adapter_count > 0 and failed_adapters == adapter_count:
        return 1
    return 0
