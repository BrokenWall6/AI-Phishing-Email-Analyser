"""Unit tests for the individual analyzers."""

import textwrap

from app.config import settings
from app.services.analyzers.brand_mismatch_analyzer import BrandMismatchAnalyzer
from app.services.analyzers.content_analyzer import ContentAnalyzer
from app.services.analyzers.dns_analyzer import DNSAnalyzer
from app.services.analyzers.header_analyzer import HeaderAnalyzer
from app.services.analyzers.whois_analyzer import WhoisAnalyzer
from app.services.email_parser import EmailParser
from app.services.url_analyzer import URLAnalyzer
from app.services.url_extractor import URLExtractor


# ---------------------------------------------------------------- URLs

def test_typosquatted_paypal_is_high_risk():
    result = URLAnalyzer().analyze("http://paypa1.xyz/login")
    assert result["risk_score"] >= 45
    assert any("typosquatting of paypal" in f for f in result["findings"])


def test_brand_inside_unrelated_domain():
    result = URLAnalyzer().analyze("https://paypal-secure-login.xyz/login")
    assert any("Brand impersonation of paypal" in f for f in result["findings"])


def test_legitimate_brand_domain_is_safe():
    assert URLAnalyzer().analyze("https://www.google.com/")["risk_score"] == 0
    assert URLAnalyzer().analyze("https://accounts.google.com/signin")["risk_score"] == 0


def test_common_word_is_not_typosquatting():
    result = URLAnalyzer().analyze("https://apply.example.org/")
    assert not any("typosquatting" in f for f in result["findings"])


def test_direct_ip_scored_once():
    result = URLAnalyzer().analyze("https://185.199.108.153/")
    assert result["risk_score"] == 25


def test_at_in_query_is_not_obfuscation():
    result = URLAnalyzer().analyze("https://example.com/unsubscribe?email=a@b.com")
    assert not any("@ symbol" in f for f in result["findings"])


def test_url_extractor_handles_markdown_and_html():
    extractor = URLExtractor()
    assert extractor.extract_urls("[http://a.com/x](http://a.com/x)") == ["http://a.com/x"]
    assert extractor.extract_urls("", '<a href="https://b.org/p?q=1&amp;r=2">x</a>') == [
        "https://b.org/p?q=1&r=2"
    ]


# ---------------------------------------------------------------- WHOIS / DNS

def test_whois_failure_is_unknown_not_risk(monkeypatch):
    import app.services.analyzers.whois_analyzer as module

    def boom(domain):
        raise TimeoutError("timed out")

    monkeypatch.setattr(settings, "ENABLE_NETWORK_LOOKUPS", True)
    monkeypatch.setattr(module.whois, "whois", boom)
    module._cached_whois_tuple.cache_clear()

    result = WhoisAnalyzer().analyze("www.some-unique-test-domain.com")
    assert result["status"] == "unavailable"
    assert result["risk_score"] == 0
    assert result["domain"] == "some-unique-test-domain.com"


def test_whois_naive_creation_date_does_not_crash(monkeypatch):
    import datetime as dt
    import app.services.analyzers.whois_analyzer as module

    class Record:
        registrar = "Example Registrar"
        creation_date = dt.datetime.now() - dt.timedelta(days=3)   # naive datetime
        expiration_date = None

    monkeypatch.setattr(settings, "ENABLE_NETWORK_LOOKUPS", True)
    monkeypatch.setattr(module.whois, "whois", lambda d: Record())
    module._cached_whois_tuple.cache_clear()

    result = WhoisAnalyzer().analyze("brand-new-domain-test.xyz")
    assert result["status"] == "ok"
    assert result["risk_score"] == 30


def test_dns_disabled_returns_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_NETWORK_LOOKUPS", False)
    result = DNSAnalyzer().analyze("example.com")
    assert result["status"] == "unavailable"
    assert result["risk_score"] == 0


# ---------------------------------------------------------------- Headers

def test_reply_to_mismatch_is_flagged():
    result = HeaderAnalyzer().analyze({"from": "support@paypal.com", "reply_to": "attacker@gmail.com"})
    assert result["risk_score"] >= 20
    assert result["reply_to_status"] == "Mismatch"


def test_mailing_list_reply_to_is_not_flagged():
    email = {
        "from": "Alice <alice@company.com>",
        "reply_to": "ilug@linux.ie",
        "list_id": "<ilug.linux.ie>",
    }
    assert HeaderAnalyzer().analyze(email)["risk_score"] == 0


def test_reply_to_subdomain_is_same_organisation():
    email = {"from": "news@mail.example.com", "reply_to": "help@example.com"}
    assert HeaderAnalyzer().analyze(email)["risk_score"] == 0


def test_authentication_failure_is_flagged():
    email = {
        "from": "billing@bank.com",
        "authentication_results": "mx.google.com; spf=fail smtp.mailfrom=bank.com; dkim=fail",
    }
    assert HeaderAnalyzer().analyze(email)["risk_score"] >= 40


# ---------------------------------------------------------------- Brand / content

def test_display_name_brand_spoof():
    email = {"from": "PayPal Security <alert@secure-mail-check.net>", "subject": "Notice", "body": ""}
    result = BrandMismatchAnalyzer().analyze(email, [])
    assert result["risk_score"] >= 35


def test_newsletter_mentioning_brand_is_not_impersonation():
    email = {
        "from": "Lockergnome Apple Core <subscriptions@lockergnome.com>",
        "subject": "Today's Apple tips",
        "body": "Apple released a new iMac. Read more at http://www.lockergnome.com/apple",
    }
    result = BrandMismatchAnalyzer().analyze(
        email, ["http://www.lockergnome.com/apple"], mailing_list=True
    )
    assert result["risk_score"] == 0


def test_credential_request_language():
    email = {
        "subject": "Account suspended",
        "body": "Your account has been suspended. Verify your account within 24 hours "
                "immediately or it will be closed.",
    }
    result = ContentAnalyzer().analyze(email)
    assert "credential_request" in result["indicators"]
    assert "account_threat" in result["indicators"]
    assert result["risk_score"] >= 35


def test_deceptive_link_text():
    html = '<a href="http://203.0.113.9/login">https://www.paypal.com/signin</a>'
    result = ContentAnalyzer().analyze({"subject": "", "body": "", "html_body": html})
    assert "deceptive_links" in result["indicators"]
    assert result["risk_score"] >= 25


def test_normal_email_has_no_content_risk():
    email = {"subject": "Lunch?", "body": "Hi Sam, are we still on for lunch on Friday? Cheers, Ana"}
    assert ContentAnalyzer().analyze(email)["risk_score"] == 0


# ---------------------------------------------------------------- Parser

def test_html_only_email_body_is_parsed(tmp_path):
    raw = textwrap.dedent("""\
        From: Shop <deals@shop.example>
        To: you@example.com
        Subject: Offer
        MIME-Version: 1.0
        Content-Type: text/html; charset=utf-8

        <html><body><p>Hello</p><a href="http://deal.example.xyz/win">Click</a></body></html>
        """)
    path = tmp_path / "html_only.eml"
    path.write_text(raw)

    email = EmailParser().parse_email(str(path))
    assert "Hello" in email["body"]
    assert "http://deal.example.xyz/win" in URLExtractor().extract_urls(email["body"], email["html_body"])


# ---------------------------------------------------------------- Look-alikes, hosting, greetings

def test_lookalike_brand_in_sender_name():
    email = {"from": "lCIoud-Support <noreply@sportlomo.com>", "subject": "Final reminder", "body": ""}
    assert BrandMismatchAnalyzer().analyze(email, [])["risk_score"] >= 35


def test_display_name_with_comma_is_parsed():
    email = {"from": "Facebook, _ <s0rc1@zu5c7zvm6a.com>", "subject": "", "body": ""}
    assert BrandMismatchAnalyzer().analyze(email, [])["risk_score"] >= 35


def test_stylised_letters_and_address_greeting():
    email = {"from": "Sirius XM <a@b.example>", "subject": "𝗬𝗼𝘂𝗿 membership has expired",
             "body": "Hi bob@example.com, please update your payment method"}
    result = ContentAnalyzer().analyze(email)
    assert result["indicators"].get("obfuscated_text")
    assert result["indicators"].get("address_greeting")


def test_russian_text_is_not_flagged_as_obfuscated():
    email = {"from": "Магазин <shop@example.ru>", "subject": "Ваш заказ Amazon отправлен", "body": "Спасибо"}
    assert not ContentAnalyzer().analyze(email)["indicators"].get("obfuscated_text")


def test_abused_hosting_page():
    assert URLAnalyzer().analyze("https://storage.googleapis.com/x/login.html#abc")["risk_score"] >= 20
    assert URLAnalyzer().analyze("https://storage.googleapis.com/x/logo.png")["risk_score"] == 0


def test_random_sender_address():
    assert HeaderAnalyzer().analyze({"from": "AD8XWZK55Q@approachcheese.pro"})["risk_score"] >= 10
    assert HeaderAnalyzer().analyze({"from": "John <john.smith@example.com>"})["risk_score"] == 0
