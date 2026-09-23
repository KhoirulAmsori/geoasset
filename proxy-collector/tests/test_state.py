from state import (
    STATUS_ACTIVE,
    STATUS_INVALID,
    ChannelState,
    State,
    load_state,
    merge_state,
    save_state,
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


def test_merge_is_additive():
    base = State(channels={"old": ChannelState(last_id=5)})
    merged = merge_state(base, {"new": ChannelState(last_id=0)})
    assert set(merged.channels) == {"old", "new"}
    assert merged.channels["old"].last_id == 5


def test_merge_updates_existing():
    base = State(channels={"a": ChannelState(last_id=1)})
    merged = merge_state(base, {"a": ChannelState(last_id=9)})
    assert merged.channels["a"].last_id == 9


def test_last_id_never_decreases_on_merge_contract():
    base = State(channels={"a": ChannelState(last_id=9, last_ok="keep")})
    merged = merge_state(base, {"a": ChannelState(last_id=3, status=STATUS_INVALID)})
    assert merged.channels["a"].last_id == 9
    assert merged.channels["a"].last_ok == "keep"
    assert merged.channels["a"].status == STATUS_INVALID
