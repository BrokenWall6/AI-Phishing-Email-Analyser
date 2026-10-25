import html
import re


class URLExtractor:
    """
    Extracts http/https URLs from email text (and optionally raw HTML).

    Handles Markdown links, dataset escaping (\\. \\/ \\&), HTML href
    attributes and HTML entities, and de-duplicates the result while
    keeping the original order.
    """

    MARKDOWN_PATTERN = re.compile(r'\]\s*\(\s*(https?://[^)\s]+)', re.I)
    HREF_PATTERN = re.compile(r'href\s*=\s*["\']?\s*(https?://[^"\'\s>]+)', re.I)
    NORMAL_PATTERN = re.compile(r'https?://[^\s<>"\'\[\]\\(){}|^`]+', re.I)

    def extract_urls(self, text, html_text=""):

        urls = []

        def add(url):
            url = self._clean_url(url)
            if url and url not in urls:
                urls.append(url)

        text = text or ""

        for url in self.MARKDOWN_PATTERN.findall(text):
            add(url)

        for url in self.HREF_PATTERN.findall(html_text or ""):
            add(url)

        # Undo common dataset escaping before the generic match so that
        # "http:\/\/example\.com" is found too.
        unescaped = (
            text.replace(r"\/", "/")
            .replace(r"\.", ".")
            .replace(r"\:", ":")
            .replace(r"\&", "&")
        )

        for url in self.NORMAL_PATTERN.findall(unescaped):
            add(url)

        return urls

    def _clean_url(self, url):

        url = html.unescape(url)

        # Remove dataset escaping.
        url = url.replace(r'\&', '&')
        url = url.replace(r'\.', '.')
        url = url.replace(r'\/', '/')
        url = url.replace(r'\:', ':')

        # Remove trailing punctuation.
        url = url.rstrip('.,;:!?\'">*')

        # A bare scheme ("http://") is not a URL.
        if re.fullmatch(r'https?://', url, re.I):
            return ""

        return url
