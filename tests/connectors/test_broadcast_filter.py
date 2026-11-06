"""Tombstone filter — drops Kafka null/empty values, decodes valid bytes."""

from app.connectors.broadcast_filter import filter_and_decode_tombstones


def test_null_value_is_dropped():
    """Real Kafka tombstone (`producer.send(..., value=None)`) reaches the
    deserializer as Python `None` and must yield nothing."""
    assert list(filter_and_decode_tombstones(None)) == []


def test_empty_bytes_is_dropped():
    assert list(filter_and_decode_tombstones(b"")) == []


def test_valid_payload_is_decoded():
    payload = b'{"id":"hos-1","seqs":[]}'
    assert list(filter_and_decode_tombstones(payload)) == [payload.decode("utf-8")]


def test_unicode_payload_is_decoded():
    payload = '{"name":"АРТ28"}'.encode()
    assert list(filter_and_decode_tombstones(payload)) == ['{"name":"АРТ28"}']
