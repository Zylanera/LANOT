from lanot_agent.buffer import DiskBuffer


def test_buffer_cap_drops_oldest(tmp_path):
    b = DiskBuffer(tmp_path, max_bytes=1000)
    for i in range(5):
        b.push("logs", bytes([65 + i]) * 300)
    assert b.size_bytes() <= 1000
    first = b.peek()
    assert first is not None and first[2] == b"C" * 300 


def test_buffer_fifo_and_ack(tmp_path):
    b = DiskBuffer(tmp_path)
    b.push("metrics", b"one")
    b.push("state", b"two")
    id1, kind1, data1 = b.peek()
    assert (kind1, data1) == ("metrics", b"one")
    b.ack(id1)
    _, kind2, data2 = b.peek()
    assert (kind2, data2) == ("state", b"two")


def test_buffer_survives_restart_and_keeps_order(tmp_path):
    DiskBuffer(tmp_path).push("logs", b"a")
    b = DiskBuffer(tmp_path)
    b.push("logs", b"b")
    seen = []
    while (item := b.peek()) is not None:
        seen.append(item[2])
        b.ack(item[0])
    assert seen == [b"a", b"b"]
    assert b.size_bytes() == 0
