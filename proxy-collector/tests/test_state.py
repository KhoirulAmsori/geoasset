from state import (
    STATUS_ACTIVE,
    STATUS_INVALID,
    ChannelState,
    State,
    apply_run,
    is_due,
    load_state,
    save_state,
    select_channels,
)


def test_load_missing_file_returns_empty(tmp_path):
    st = load_state(str(tmp_path / "nope.json"))
    assert st.channels == {}


def test_load_corrupt_file_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_state(str(p)).channels == {}


def test_load_valid_json_wrong_shape_returns_empty(tmp_path):
    p = tmp_path / "list.json"
    p.write_text('["bogus"]', encoding="utf-8")
    assert load_state(str(p)).channels == {}


def test_load_bad_version_does_not_crash(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text('{"version": "abc", "channels": {}}', encoding="utf-8")
    assert load_state(str(p)).channels == {}


def test_load_channels_wrong_type_returns_empty(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text('{"version": 1, "channels": ["x"]}', encoding="utf-8")
    assert load_state(str(p)).channels == {}


def test_round_trip(tmp_path):
    p = tmp_path / "channels.json"
    st = State(channels={
        "hope_net": ChannelState(last_id=6900, status=STATUS_ACTIVE, last_ok="2026-09-23T10:00:00Z"),
        "dead": ChannelState(last_id=12, status=STATUS_INVALID),
    })
    save_state(str(p), st)
    loaded = load_state(str(p))
    assert loaded.channels["hope_net"].last_id == 6900
    assert loaded.channels["hope_net"].status == STATUS_ACTIVE
    assert loaded.channels["dead"].status == STATUS_INVALID


def test_apply_run_is_additive():
    st = apply_run(State(run_count=0, channels={"old": ChannelState(last_id=5)}),
                   {"new": ChannelState(last_id=0)}, retire_after=10, retry_after=30)
    assert set(st.channels) == {"old", "new"}
    assert st.channels["old"].last_id == 5


def test_apply_run_updates_existing():
    base = State(run_count=0, channels={"a": ChannelState(last_id=1)})
    st = apply_run(base, {"a": ChannelState(last_id=9)}, retire_after=10, retry_after=30)
    assert st.channels["a"].last_id == 9


def test_round_trip_pruning_fields(tmp_path):
    p = tmp_path / "channels.json"
    st = State(
        channels={"a": ChannelState(fail_count=3, retired_at=7)},
        run_count=12,
    )
    save_state(str(p), st)
    loaded = load_state(str(p))
    assert loaded.run_count == 12
    assert loaded.channels["a"].fail_count == 3
    assert loaded.channels["a"].retired_at == 7


def test_load_state_normalizes_case_duplicate_keys(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text(
        '{"run_count": 3, "channels": {'
        '"AI_DUET": {"last_id": 0},'
        '"ai_duet": {"last_id": 7, "status": "active", "last_ok": "t"}'
        "}}",
        encoding="utf-8",
    )
    st = load_state(str(p))
    assert set(st.channels) == {"ai_duet"}
    assert st.channels["ai_duet"].last_id == 7


def test_load_state_merges_keeping_more_progress(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text(
        '{"channels": {'
        '"X": {"last_id": 2, "fail_count": 4},'
        '"x": {"last_id": 9, "fail_count": 1}'
        "}}",
        encoding="utf-8",
    )
    st = load_state(str(p))
    assert st.channels["x"].last_id == 9


def test_load_state_prefers_active_on_tie(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text(
        '{"channels": {'
        '"Y": {"last_id": 5, "status": "invalid", "fail_count": 3},'
        '"y": {"last_id": 5, "status": "active"}'
        "}}",
        encoding="utf-8",
    )
    st = load_state(str(p))
    assert st.channels["y"].status == STATUS_ACTIVE


def test_load_state_lowercases_single_uppercase_key(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text('{"channels": {"MixedCase": {"last_id": 4}}}', encoding="utf-8")
    st = load_state(str(p))
    assert set(st.channels) == {"mixedcase"}
    assert st.channels["mixedcase"].last_id == 4

    st = apply_run(State(run_count=4), {}, retire_after=10, retry_after=30)
    assert st.run_count == 5


def test_apply_run_active_resets_fail_count_and_retirement():
    base = State(run_count=1, channels={"a": ChannelState(fail_count=9, retired_at=1)})
    st = apply_run(base, {"a": ChannelState(status=STATUS_ACTIVE)}, retire_after=10, retry_after=30)
    assert st.channels["a"].fail_count == 0
    assert st.channels["a"].retired_at == 0


def test_apply_run_invalid_increments_fail_count():
    base = State(run_count=1, channels={"a": ChannelState(fail_count=2)})
    st = apply_run(base, {"a": ChannelState(status=STATUS_INVALID)}, retire_after=10, retry_after=30)
    assert st.channels["a"].fail_count == 3
    assert st.channels["a"].retired_at == 0


def test_apply_run_retires_at_threshold():
    base = State(run_count=1, channels={"a": ChannelState(fail_count=9)})
    st = apply_run(base, {"a": ChannelState(status=STATUS_INVALID)}, retire_after=10, retry_after=30)
    assert st.channels["a"].retired_at == st.run_count


def test_apply_run_leaves_unscraped_channels_untouched():
    base = State(run_count=5, channels={"gone": ChannelState(fail_count=11, retired_at=2)})
    st = apply_run(base, {}, retire_after=10, retry_after=30)
    assert st.channels["gone"].fail_count == 11
    assert st.channels["gone"].retired_at == 2


def test_apply_run_keeps_last_id_monotonic():
    base = State(run_count=1, channels={"a": ChannelState(last_id=50, last_ok="keep")})
    st = apply_run(base, {"a": ChannelState(last_id=10, status=STATUS_INVALID)}, retire_after=10, retry_after=30)
    assert st.channels["a"].last_id == 50
    assert st.channels["a"].last_ok == "keep"


def test_is_due_never_retired():
    st = State(run_count=100)
    assert is_due(st, "a", retry_after=30) is True


def test_is_due_retired_and_not_yet_due():
    st = State(run_count=20, channels={"a": ChannelState(retired_at=10)})
    assert is_due(st, "a", retry_after=30) is False


def test_is_due_retired_and_due():
    st = State(run_count=40, channels={"a": ChannelState(retired_at=10)})
    assert is_due(st, "a", retry_after=30) is True


def test_select_channels_skips_retired_seed():
    st = State(run_count=20, channels={"deadseed": ChannelState(retired_at=10)})
    got = select_channels(["deadseed", "good"], st, retry_after=30)
    assert got == ["good"]


def test_select_channels_includes_due_retired():
    st = State(run_count=40, channels={"deadseed": ChannelState(retired_at=10)})
    got = select_channels(["deadseed"], st, retry_after=30)
    assert got == ["deadseed"]


def test_select_channels_lowercases_and_dedupes():
    st = State(run_count=0, channels={"Mixed": ChannelState()})
    got = select_channels(["Mixed", "mixed"], st, retry_after=30)
    assert got == ["mixed"]
