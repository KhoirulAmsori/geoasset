from adapters.telegram import discover_usernames, parse_messages

PAGE = """
<div class="tgme_widget_message" data-post="hope_net/100">
  <div class="tgme_widget_message_text">vless://a@1.1.1.1:443#A</div>
</div>
<div class="tgme_widget_message" data-post="hope_net/101">
  <div class="tgme_widget_message_text">no config here</div>
</div>
<div class="tgme_widget_message" data-post="hope_net/102">
  <div class="tgme_widget_message_text">vmess://eyJhIjoxfQ==<br/>join @some_channel</div>
</div>
"""


def test_parse_messages_ids_and_text():
    msgs = parse_messages(PAGE)
    assert [m.id for m in msgs] == [100, 101, 102]
    assert "vless://a@1.1.1.1:443#A" in msgs[0].text


def test_parse_messages_sorted_ascending():
    shuffled = """
    <div class="tgme_widget_message" data-post="c/9"><div class="tgme_widget_message_text">x</div></div>
    <div class="tgme_widget_message" data-post="c/3"><div class="tgme_widget_message_text">y</div></div>
    """
    assert [m.id for m in parse_messages(shuffled)] == [3, 9]


def test_parse_messages_without_data_post_is_empty():
    html = '<div class="tgme_widget_message"><div class="tgme_widget_message_text">vless://a@1.2.3.4:443#A</div></div>'
    assert parse_messages(html) == []


def test_parse_messages_missing_text_block():
    html = '<div class="tgme_widget_message" data-post="c/5"></div>'
    msgs = parse_messages(html)
    assert len(msgs) == 1
    assert msgs[0].text == ""


def test_discover_usernames_variants():
    text = "join @hope_net and t.me/another_chan and %40third_chan and telegram.me/fourth_chan"
    got = set(discover_usernames(text))
    assert {"hope_net", "another_chan", "third_chan", "fourth_chan"} <= got


def test_discover_usernames_ignores_short():
    assert discover_usernames("@abc t.me/xy") == []
