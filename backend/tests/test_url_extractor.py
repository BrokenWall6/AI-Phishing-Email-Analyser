from app.services.url_extractor import URLExtractor


extractor = URLExtractor()


def test_markdown_link_is_not_duplicated():
    text = "[http://website.e365.cc/savequote/](http://website.e365.cc/savequote/)"
    assert extractor.extract_urls(text) == ["http://website.e365.cc/savequote/"]


def test_link_inside_sentence():
    text = "Text before [http://google.com/path](http://google.com/path) and text after"
    assert extractor.extract_urls(text) == ["http://google.com/path"]


def test_query_string_is_kept():
    text = "[http://www.adclick.ws/p.cfm?o=245&s=pk002](http://www.adclick.ws/p.cfm?o=245&s=pk002)"
    assert extractor.extract_urls(text) == ["http://www.adclick.ws/p.cfm?o=245&s=pk002"]


def test_escaped_url_from_dataset():
    assert extractor.extract_urls(r"see http:\/\/www.example\.com\/test") == ["http://www.example.com/test"]


def test_trailing_punctuation_is_removed():
    assert extractor.extract_urls("Login: http://example.com/login.") == ["http://example.com/login"]


def test_bare_scheme_is_ignored():
    assert extractor.extract_urls("http:// and nothing else") == []
