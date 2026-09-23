from adapters.telegram import TelegramAdapter
from config import Config
from state import STATUS_ACTIVE, STATUS_INVALID, ChannelState


def make_cfg(**over):
    base = dict(
        collected_file="c", channels_state_file="s", seed_file="seed",
        subscriptions_file="sub", webpages_file="web", telegram_depth=3,
        concurrency=8, timeout=15, http_retry=2, max_new_channels=50,
        min_collected=0, skip_push_flag="skip",
    )
    base.update(over)
    return Config(**base)


def page(*ids_texts):
    parts = []
    for mid, text in ids_texts:
        parts.append(
            f'<div class="tgme_widget_message" data-post="ch/{mid}">'
            f'<div class="tgme_widget_message_text">{text}</div></div>'
        )
    return "".join(parts)


def test_steady_state_only_processes_new_messages():
    pages = {None: page((100, "vless://a@1.1.1.1:443#A"),
                        (101, "vless://b@2.2.2.2:443#B"))}
    calls = []

    def fetch(channel, before):
        calls.append(before)
        return pages.get(before)

    adapter = TelegramAdapter(
        ["ch"], {"ch": ChannelState(last_id=100)}, fetch, make_cfg()
    )
    res = adapter.fetch()
    assert res.configs == ["vless://b@2.2.2.2:443#B"]
    assert calls == [None]
    assert res.state_updates["ch"].last_id == 101
    assert res.state_updates["ch"].status == STATUS_ACTIVE


def test_no_new_messages_makes_no_extra_request():
    calls = []

    def fetch(channel, before):
        calls.append(before)
        return page((100, "vless://a@1.1.1.1:443#A"))

    adapter = TelegramAdapter(
        ["ch"], {"ch": ChannelState(last_id=100)}, fetch, make_cfg()
    )
    res = adapter.fetch()
    assert res.configs == []
    assert calls == [None]
    assert res.state_updates["ch"].last_id == 100


def test_new_channel_backfills_until_depth():
    pages = {
        None: page((102, "vless://c@3.3.3.3:443#C")),
        102: page((101, "vless://b@2.2.2.2:443#B")),
        101: page((100, "vless://a@1.1.1.1:443#A")),
    }
    calls = []

    def fetch(channel, before):
        calls.append(before)
        return pages.get(before)

    adapter = TelegramAdapter(["ch"], {}, fetch, make_cfg(telegram_depth=3))
    res = adapter.fetch()
    assert set(res.configs) == {
        "vless://a@1.1.1.1:443#A",
        "vless://b@2.2.2.2:443#B",
        "vless://c@3.3.3.3:443#C",
    }
    assert calls == [None, 102, 101]
    assert res.state_updates["ch"].last_id == 102


def test_gap_is_closed_only_until_cursor():
    pages = {
        None: page((105, "vless://e@5.5.5.5:443#E")),
        105: page((104, "vless://d@4.4.4.4:443#D")),
        104: page((100, "vless://old@1.1.1.1:443#OLD")),
    }
    calls = []

    def fetch(channel, before):
        calls.append(before)
        return pages.get(before)

    adapter = TelegramAdapter(
        ["ch"], {"ch": ChannelState(last_id=103)}, fetch, make_cfg()
    )
    res = adapter.fetch()
    assert set(res.configs) == {
        "vless://d@4.4.4.4:443#D",
        "vless://e@5.5.5.5:443#E",
    }
    assert calls == [None, 105, 104]


def test_fetch_failure_marks_invalid():
    adapter = TelegramAdapter(
        ["ch"], {"ch": ChannelState(last_id=5)}, lambda c, b: None, make_cfg()
    )
    res = adapter.fetch()
    assert res.state_updates["ch"].status == STATUS_INVALID
    assert res.errors


def test_empty_page_marks_invalid():
    adapter = TelegramAdapter(
        ["ch"], {"ch": ChannelState(last_id=0)}, lambda c, b: "", make_cfg()
    )
    res = adapter.fetch()
    assert res.state_updates["ch"].status == STATUS_INVALID


def test_discovery_backfills_new_channel_same_run():
    def fetch(channel, before):
        if channel == "seed_ch":
            return page((10, "vless://a@1.1.1.1:443#A see @new_channel"))
        if channel == "new_channel":
            return page((1, "vless://n@9.9.9.9:443#N"))
        return None

    adapter = TelegramAdapter(
        ["seed_ch"], {"seed_ch": ChannelState(last_id=9)}, fetch, make_cfg()
    )
    res = adapter.fetch()
    assert "vless://n@9.9.9.9:443#N" in res.configs
    assert res.state_updates["new_channel"].last_id == 1
    assert "new_channel" in res.discovered


def test_discovery_respects_max_new_channels():
    def fetch(channel, before):
        if channel == "seed_ch":
            return page((10, "join @chan_one @chan_two @chan_three"))
        return page((1, "vless://n@9.9.9.9:443#N"))

    adapter = TelegramAdapter(
        ["seed_ch"], {"seed_ch": ChannelState(last_id=9)}, fetch,
        make_cfg(max_new_channels=1),
    )
    res = adapter.fetch()
    discovered = {c: s for c, s in res.state_updates.items() if c != "seed_ch"}
    backfilled = [c for c, s in discovered.items() if s.last_id == 1]
    overflow = [c for c, s in discovered.items() if s.last_id == 0]
    assert len(backfilled) == 1
    assert len(overflow) == 2
