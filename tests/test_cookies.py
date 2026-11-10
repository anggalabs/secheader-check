"""Unit test untuk pemeriksaan cookie (tanpa jaringan)."""

import email.message
import unittest

from secheader_check.cookies import (
    check_cookies, cookie_problems, get_set_cookie_headers, parse_set_cookie,
)
from secheader_check.headers import FAIL, PASS, WARN


class TestParsing(unittest.TestCase):
    def test_parse_attributes(self):
        c = parse_set_cookie("SID=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(c.name, "SID")
        self.assertTrue(c.secure and c.httponly)
        self.assertEqual(c.samesite, "lax")

    def test_expires_comma_not_split(self):
        # Koma di Expires tidak boleh memecah cookie.
        c = parse_set_cookie("id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure")
        self.assertEqual(c.name, "id")
        self.assertTrue(c.secure)

    def test_multiple_headers_from_http_message(self):
        msg = email.message.Message()
        msg["Set-Cookie"] = "a=1; Secure"
        msg["Set-Cookie"] = "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
        self.assertEqual(len(get_set_cookie_headers(msg)), 2)


class TestProblems(unittest.TestCase):
    def test_csrf_cookie_may_skip_httponly(self):
        c = parse_set_cookie("XSRF-TOKEN=x; Secure; SameSite=Lax")
        self.assertEqual(cookie_problems(c, True), [])

    def test_samesite_none_without_secure(self):
        c = parse_set_cookie("x=1; HttpOnly; SameSite=None")
        self.assertTrue(any("SameSite=None" in p for p in cookie_problems(c, False)))

    def test_secure_not_required_on_http(self):
        c = parse_set_cookie("x=1; HttpOnly; SameSite=Lax")
        self.assertEqual(cookie_problems(c, False), [])


class TestCheckCookies(unittest.TestCase):
    def test_no_cookies(self):
        self.assertEqual(check_cookies({}, True).status, PASS)

    def test_good_session_cookie(self):
        h = {"Set-Cookie": "PHPSESSID=x; Secure; HttpOnly; SameSite=Lax"}
        self.assertEqual(check_cookies(h, True).status, PASS)

    def test_weak_session_cookie_is_fail(self):
        h = {"Set-Cookie": "MoodleSession=x; path=/"}
        f = check_cookies(h, True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("MoodleSession", f.message)

    def test_weak_non_session_cookie_is_warn(self):
        h = {"Set-Cookie": ["theme=dark; path=/"]}
        self.assertEqual(check_cookies(h, True).status, WARN)

    def test_cookie_value_never_shown(self):
        h = {"Set-Cookie": "sessionid=RAHASIA123; path=/"}
        self.assertNotIn("RAHASIA123", check_cookies(h, True).message)


if __name__ == "__main__":
    unittest.main()
