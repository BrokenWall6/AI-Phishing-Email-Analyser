import html
import re
from email import policy
from email.parser import BytesParser


class EmailParser:
    """
    Parses an .eml file into a plain dictionary used by the analyzers.

    HTML-only emails fall back to a tag-stripped copy of the HTML, and the
    raw HTML is kept for link extraction. List, reply and authentication
    headers are included so the header analyzer can tell mailing lists and
    real replies apart from spoofed mail.
    """

    def parse_email(self, filepath):

        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        text_body, html_body = self.extract_bodies(msg)

        # The analyzers work on "body". Prefer text/plain; if the email
        # only has HTML, use a tag-stripped version of the HTML.
        body = text_body if text_body.strip() else self.html_to_text(html_body)

        return {
            "from": self._header(msg, "From"),
            "to": self._header(msg, "To"),
            "subject": self._header(msg, "Subject"),
            "reply_to": self._header(msg, "Reply-To"),
            "date": self._header(msg, "Date"),
            "return_path": self._header(msg, "Return-Path"),
            "in_reply_to": self._header(msg, "In-Reply-To"),
            "references": self._header(msg, "References"),
            "list_id": self._header(msg, "List-Id"),
            "list_unsubscribe": self._header(msg, "List-Unsubscribe"),
            "precedence": self._header(msg, "Precedence"),
            "authentication_results": self._header(msg, "Authentication-Results"),
            "received_spf": self._header(msg, "Received-SPF"),
            "body": body,
            "html_body": html_body,
        }

    # ------------------------------------------------------------------

    def _header(self, msg, name):

        try:
            value = msg.get(name, "")
            return str(value) if value is not None else ""
        except Exception:
            # Malformed headers should never stop the analysis.
            raw = msg.get_all(name) or [""]
            return str(raw[0])

    def _part_text(self, part):

        try:
            return part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "latin-1"
            try:
                return payload.decode(charset, errors="replace")
            except LookupError:
                return payload.decode("latin-1", errors="replace")

    def extract_bodies(self, msg):

        text_parts = []
        html_parts = []

        parts = msg.walk() if msg.is_multipart() else [msg]

        for part in parts:

            if part.is_multipart():
                continue

            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type == "text/plain":
                text_parts.append(self._part_text(part))

            elif content_type == "text/html":
                html_parts.append(self._part_text(part))

        text_body = "\n".join(p for p in text_parts if isinstance(p, str))
        html_body = "\n".join(p for p in html_parts if isinstance(p, str))

        # Some old emails are labelled text/plain but actually contain HTML.
        if not html_body and re.search(r"<\s*(html|body|a\s+href)", text_body, re.I):
            html_body = text_body
            text_body = self.html_to_text(text_body)

        return text_body, html_body

    @staticmethod
    def html_to_text(raw_html):

        if not raw_html:
            return ""

        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_html)

        # Keep link targets visible to the URL extractor.
        text = re.sub(
            r'(?is)<a\s[^>]*href\s*=\s*["\']?([^"\'\s>]+)["\']?[^>]*>',
            r" \1 ",
            text,
        )

        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = html.unescape(text)
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)

        return text.strip()
