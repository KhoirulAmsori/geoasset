from adapters.base import FetchResult
from state import ChannelState


def test_fetch_result_defaults_are_independent():
    a = FetchResult()
    b = FetchResult()
    a.configs.append("x")
    assert b.configs == []
    assert a.discovered == []
    assert a.errors == []
    assert a.state_updates == {}


def test_fetch_result_holds_state_updates():
    r = FetchResult(state_updates={"ch": ChannelState(last_id=3)})
    assert r.state_updates["ch"].last_id == 3
