"""Tests for the KQL tokenizer."""

from cdv.parser.tokenizer import tokenize


class TestSingleLineComments:
    def test_strips_single_line_comment(self):
        result = tokenize("// this is a comment\nDeviceEvents")
        assert "// this is a comment" not in result.cleaned_text
        assert "DeviceEvents" in result.cleaned_text
        assert result.has_comments is True

    def test_strips_inline_comment(self):
        result = tokenize("DeviceEvents // the table\n| where ActionType == 'x'")
        assert "//" not in result.cleaned_text
        assert "DeviceEvents" in result.cleaned_text
        assert result.has_comments is True

    def test_preserves_newline_after_comment(self):
        result = tokenize("// comment\nDeviceEvents")
        assert result.cleaned_text.startswith("\n")

    def test_no_comment_flag_when_none(self):
        result = tokenize("DeviceEvents | where ActionType == 'x'")
        assert result.has_comments is False


class TestMultiLineComments:
    def test_strips_block_comment(self):
        result = tokenize("/* block comment */DeviceEvents")
        assert "block comment" not in result.cleaned_text
        assert "DeviceEvents" in result.cleaned_text
        assert result.has_comments is True

    def test_strips_multiline_block(self):
        kql = "/* line 1\nline 2\nline 3 */\nDeviceEvents"
        result = tokenize(kql)
        assert "line 1" not in result.cleaned_text
        assert "DeviceEvents" in result.cleaned_text
        assert result.has_comments is True

    def test_replaces_block_comment_with_space(self):
        result = tokenize("A/* comment */B")
        assert "A" in result.cleaned_text
        assert "B" in result.cleaned_text


class TestStringLiterals:
    def test_preserves_single_quoted_string_value(self):
        result = tokenize("where ActionType == 'ProcessCreated'")
        assert len(result.string_literals) == 1
        assert result.string_literals[0] == "ProcessCreated"

    def test_preserves_double_quoted_string_value(self):
        result = tokenize('where ActionType == "ProcessCreated"')
        assert len(result.string_literals) == 1
        assert result.string_literals[0] == "ProcessCreated"

    def test_replaces_string_content_with_placeholder(self):
        result = tokenize("where ActionType == 'ProcessCreated'")
        assert "ProcessCreated" not in result.cleaned_text
        assert "__STR0__" in result.cleaned_text

    def test_handles_escaped_chars_in_string(self):
        result = tokenize(r"where Name == 'it\'s'")
        assert len(result.string_literals) == 1

    def test_multiple_strings(self):
        result = tokenize("where A == 'x' and B == 'y'")
        assert len(result.string_literals) == 2
        assert result.string_literals[0] == "x"
        assert result.string_literals[1] == "y"

    def test_string_with_comment_chars_not_treated_as_comment(self):
        result = tokenize("where A == '// not a comment'")
        assert result.has_comments is False
        assert result.string_literals[0] == "// not a comment"


class TestOriginalText:
    def test_original_text_preserved(self):
        original = "// comment\nDeviceEvents | where ActionType == 'x'"
        result = tokenize(original)
        assert result.original_text == original
