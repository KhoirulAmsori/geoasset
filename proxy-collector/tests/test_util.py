import os

from util import atomic_write


def test_atomic_write_creates_file(tmp_path):
    p = tmp_path / "out.txt"
    atomic_write(str(p), "hello\n")
    assert p.read_text(encoding="utf-8") == "hello\n"


def test_atomic_write_replaces_and_leaves_no_temp(tmp_path):
    p = tmp_path / "out.txt"
    p.write_text("old", encoding="utf-8")
    atomic_write(str(p), "new")
    assert p.read_text(encoding="utf-8") == "new"
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".tmp")]
    assert leftovers == []


def test_atomic_write_creates_parent_dirs(tmp_path):
    p = tmp_path / "a" / "b" / "out.txt"
    atomic_write(str(p), "x")
    assert p.read_text(encoding="utf-8") == "x"
