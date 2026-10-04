from unittest.mock import patch

import pytest

from bypass_forge_server import RATE_LIMIT_REQ, RATE_LIMIT_WIN, rate_check, rate_table


@pytest.fixture(autouse=True)
def reset_rate_table():
    rate_table.clear()


def test_rate_check_under_limit():
    ip = "127.0.0.1"
    # Make requests up to RATE_LIMIT_REQ - 1
    for _ in range(RATE_LIMIT_REQ - 1):
        assert rate_check(ip)

    # Should still be under limit
    assert len(rate_table[ip]) == RATE_LIMIT_REQ - 1


def test_rate_check_exceed_limit():
    ip = "127.0.0.2"
    # Make requests up to RATE_LIMIT_REQ
    for _ in range(RATE_LIMIT_REQ):
        assert rate_check(ip)

    # Next request should fail
    assert not rate_check(ip)


def test_rate_check_sliding_window():
    ip = "127.0.0.3"

    # Mock time to a specific point
    with patch("time.time", return_value=100.0):
        for _ in range(RATE_LIMIT_REQ):
            assert rate_check(ip)

        # Exceeded limit
        assert not rate_check(ip)

    # Move time forward by more than RATE_LIMIT_WIN
    with patch("time.time", return_value=100.0 + RATE_LIMIT_WIN + 1.0):
        # Window expired, should be able to make requests again
        assert rate_check(ip)
        assert len(rate_table[ip]) == 1


def test_rate_check_independent_ips():
    ip1 = "127.0.0.4"
    ip2 = "127.0.0.5"

    # ip1 reaches limit
    for _ in range(RATE_LIMIT_REQ):
        assert rate_check(ip1)

    assert not rate_check(ip1)

    # ip2 should still be allowed
    assert rate_check(ip2)
