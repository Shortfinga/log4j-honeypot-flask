#!/usr/bin/env python

from app.app import check_and_handle_payloads


def test_quick_abort():
    assert check_and_handle_payloads("no payload") is False
