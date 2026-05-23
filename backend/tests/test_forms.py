"""Tests for forms.check_password_complexity()"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from forms import check_password_complexity


class TestPasswordComplexity:
    def test_valid_password(self):
        ok, msg = check_password_complexity("StrongPass1!")
        assert ok is True
        assert msg == ""

    def test_too_short(self):
        ok, _ = check_password_complexity("Ab1!")
        assert ok is False

    def test_missing_uppercase(self):
        ok, msg = check_password_complexity("lowercase1!")
        assert ok is False
        assert "A-Z" in msg or "كبير" in msg

    def test_missing_lowercase(self):
        ok, msg = check_password_complexity("UPPERCASE1!")
        assert ok is False

    def test_missing_digit(self):
        ok, msg = check_password_complexity("NoDigitsHere!")
        assert ok is False

    def test_missing_special(self):
        ok, msg = check_password_complexity("NoSpecialChars1")
        assert ok is False

    def test_exactly_10_chars_valid(self):
        ok, _ = check_password_complexity("Abcdefg1!!")
        assert ok is True

    def test_empty_password(self):
        ok, _ = check_password_complexity("")
        assert ok is False
