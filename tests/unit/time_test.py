import locale
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

from minio.time import from_http_header, to_http_header

LOCALE_LOCK = threading.Lock()
LAST_MODIFIED_STR = "Mon, 02 Mar 2015 07:28:00 GMT"
LAST_MODIFIED_DATE = datetime(
    year=2015,
    month=3,
    day=2,
    hour=7,
    minute=28,
    second=0,
    tzinfo=timezone.utc,
)


@contextmanager
def setlocale(name) -> Generator[str, Any, None]:
    with LOCALE_LOCK:
        saved = locale.setlocale(locale.LC_ALL)
        try:
            yield locale.setlocale(locale.LC_ALL, name)
        finally:
            locale.setlocale(locale.LC_ALL, saved)


class TimeutilsTest(unittest.TestCase):
    def test_from_http_header_valid_headers(self) -> None:
        for case in [
            (
                "Wed, 30 Oct 2024 09:35:00 GMT",
                datetime(
                    year=2024,
                    month=10,
                    day=30,
                    hour=9,
                    minute=35,
                    second=0,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                "Tue, 29 Oct 2024 00:35:00 GMT",
                datetime(
                    year=2024,
                    month=10,
                    day=29,
                    hour=0,
                    minute=35,
                    second=0,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                "Tue, 01 Oct 2024 22:35:22 GMT",
                datetime(
                    year=2024,
                    month=10,
                    day=1,
                    hour=22,
                    minute=35,
                    second=22,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                "Mon, 30 Sep 2024 22:35:55 GMT",
                datetime(
                    year=2024,
                    month=9,
                    day=30,
                    hour=22,
                    minute=35,
                    second=55,
                    tzinfo=timezone.utc,
                ),
            ),
        ]:
            with self.subTest(case=case):
                self.assertEqual(from_http_header(case[0]), case[1])

    def test_from_http_header_invalid_headers(self) -> None:
        for case in [
            ("Wed, 30 Oct 2024 09:35:00 GMT ", "invalid length"),
            ("Wet, 30 Oct 2024 09:35:00 GMT", "invalid weekday"),
            ("Wed  30 Oct 2024 09:35:00 GMT", "no comma after weekday"),
            ("Wed,30 Sep 2024 09:35:00 GMT ", "no space after weekday"),
            ("Wed, 30Sep 2024 09:35:00 GMT ", "no space before month"),
            ("Wed, 00 Sep 2024 09:35:00 GMT", "invalid day"),
            ("Wed, 32 Sep 2024 09:35:00 GMT", "invalid day 2"),
            ("Wed, ab Sep 2024 09:35:00 GMT", "invalid day 3"),
            ("Wed, 30 Set 2024 09:35:00 GMT", "invalid month"),
            ("Tue, 30 Set 2024 09:35:00 GMT", "name of day doesn't match"),
        ]:
            with self.subTest(case=case):
                with self.assertRaises(
                    ValueError,
                ) as exc:
                    from_http_header(case[0])
                self.assertEqual(
                    str(exc.exception),
                    f"time data {case[0]} does not match HTTP header format",
                )

    def test_from_http_header_default_locale(self) -> None:
        result_datetime = from_http_header(LAST_MODIFIED_STR)

        self.assertEqual(
            result_datetime,
            LAST_MODIFIED_DATE,
        )

    def test_from_http_header_polish_locale(self) -> None:
        try:
            with setlocale("pl_PL.utf8"):
                result_datetime = from_http_header(LAST_MODIFIED_STR)

                self.assertEqual(
                    result_datetime,
                    LAST_MODIFIED_DATE,
                )
        except locale.Error:
            self.skipTest("pl_PL.utf8 locale is not supported on this machine")

    def test_to_http_header_default_locale(self) -> None:
        self.assertEqual(
            to_http_header(LAST_MODIFIED_DATE),
            LAST_MODIFIED_STR,
        )

    def test_to_http_header_polish_locale(self) -> None:
        try:
            with setlocale("pl_PL.utf8"):
                self.assertEqual(
                    to_http_header(LAST_MODIFIED_DATE),
                    LAST_MODIFIED_STR,
                )
        except locale.Error:
            self.skipTest("pl_PL.utf8 locale is not supported on this machine")
