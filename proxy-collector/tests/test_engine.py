from adapters.base import FetchResult
from config import Config
from engine import run_collection
from state import STATUS_ACTIVE, ChannelState, load_state


def make_cfg(tmp_path, **over):
    base = dict(
        collected_file=str(tmp_path / "collected.txt"),
        channels_state_file=str(tmp_path / "channels.json"),
        seed_file="seed", subscriptions_file="sub", webpages_file="web",
        telegram_depth=3, concurrency=8, timeout=15, http_retry=2,
        max_new_channels=50, min_collected=0,
        skip_push_flag=str(tmp_path / "skip_push.flag"),
        retire_after=10, retry_after=30,
    )
    base.update(over)
    return Config(**base)


class FakeAdapter:
    def __init__(self, result):
        self.result = result

    def fetch(self):
        return self.result


def test_writes_sorted_deduped_output(tmp_path):
    cfg = make_cfg(tmp_path)
    ad = FakeAdapter(FetchResult(configs=["b", "a", "b"]))
    rc = run_collection(cfg, [ad])
    assert rc == 0
    assert open(cfg.collected_file, encoding="utf-8").read() == "a\nb\n"


def test_merges_state_updates_additively(tmp_path):
    cfg = make_cfg(tmp_path)
    from state import save_state, State
    save_state(cfg.channels_state_file, State(channels={"old": ChannelState(last_id=5)}))
    ad = FakeAdapter(FetchResult(
        configs=["x"],
        state_updates={"new": ChannelState(last_id=2, status=STATUS_ACTIVE)},
    ))
    run_collection(cfg, [ad])
    st = load_state(cfg.channels_state_file)
    assert set(st.channels) == {"old", "new"}
    assert st.channels["old"].last_id == 5


def test_min_collected_writes_skip_flag(tmp_path):
    cfg = make_cfg(tmp_path, min_collected=5)
    ad = FakeAdapter(FetchResult(configs=["a"]))
    rc = run_collection(cfg, [ad])
    assert rc == 0
    import os
    assert os.path.exists(cfg.skip_push_flag)


def test_min_collected_not_reached_no_flag_when_zero_threshold(tmp_path):
    cfg = make_cfg(tmp_path, min_collected=0)
    ad = FakeAdapter(FetchResult(configs=["a"]))
    run_collection(cfg, [ad])
    import os
    assert not os.path.exists(cfg.skip_push_flag)


def test_total_failure_returns_one(tmp_path):
    cfg = make_cfg(tmp_path)
    ad = FakeAdapter(FetchResult(configs=[], errors=["boom"]))
    assert run_collection(cfg, [ad]) == 1


def test_partial_failure_with_configs_returns_zero(tmp_path):
    cfg = make_cfg(tmp_path)
    ad = FakeAdapter(FetchResult(configs=["a"], errors=["one failed"]))
    assert run_collection(cfg, [ad]) == 0


def test_all_adapters_failed_returns_one(tmp_path):
    cfg = make_cfg(tmp_path)
    a = FakeAdapter(FetchResult(configs=[], errors=["a down"]))
    b = FakeAdapter(FetchResult(configs=[], errors=["b down"]))
    assert run_collection(cfg, [a, b]) == 1


def test_one_adapter_ok_others_failed_returns_zero(tmp_path):
    cfg = make_cfg(tmp_path)
    a = FakeAdapter(FetchResult(configs=["x"]))
    b = FakeAdapter(FetchResult(configs=[], errors=["b down"]))
    assert run_collection(cfg, [a, b]) == 0


def test_run_increments_run_count_and_tracks_invalid(tmp_path):
    from state import STATUS_INVALID, load_state, save_state, State, ChannelState
    cfg = make_cfg(tmp_path, retire_after=2)
    save_state(cfg.channels_state_file, State(run_count=4, channels={"ch": ChannelState()}))
    ad = FakeAdapter(FetchResult(
        configs=["x"],
        state_updates={"ch": ChannelState(status=STATUS_INVALID)},
    ))
    run_collection(cfg, [ad])
    st = load_state(cfg.channels_state_file)
    assert st.run_count == 5
    assert st.channels["ch"].fail_count == 1
    assert st.channels["ch"].retired_at == 0


def test_run_retires_after_threshold(tmp_path):
    from state import STATUS_INVALID, load_state, save_state, State, ChannelState
    cfg = make_cfg(tmp_path, retire_after=1)
    save_state(cfg.channels_state_file, State(run_count=4, channels={"ch": ChannelState()}))
    ad = FakeAdapter(FetchResult(
        configs=["x"],
        state_updates={"ch": ChannelState(status=STATUS_INVALID)},
    ))
    run_collection(cfg, [ad])
    st = load_state(cfg.channels_state_file)
    assert st.run_count == 5
    assert st.channels["ch"].retired_at != 0
    assert st.channels["ch"].retired_at == st.run_count
