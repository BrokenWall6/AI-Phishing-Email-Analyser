"""
Helpers for working with domains and look-alike characters.

Analyzers compare registered domains ("example.com"), not full hostnames,
so "lists.example.com" and "example.com" count as the same organisation.
"""

import ipaddress
import re
from email.utils import parseaddr
from functools import lru_cache

import tldextract

# Use the public-suffix snapshot bundled with tldextract so analysis is
# deterministic and does not try to download the list at runtime.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.de", "web.de",
    "proton.me", "protonmail.com", "yandex.com", "yandex.ru", "zoho.com",
}


@lru_cache(maxsize=4096)
def split(host_or_url):
    """Return (subdomain, domain, suffix) for a URL or hostname."""
    result = _EXTRACT(host_or_url or "")
    return (
        (result.subdomain or "").lower(),
        (result.domain or "").lower(),
        (result.suffix or "").lower(),
    )


def registered_domain(host_or_url):
    """'http://a.b.example.co.uk/x' -> 'example.co.uk' ('' if unknown)."""
    _, domain, suffix = split(host_or_url)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return ""


def domain_label(host_or_url):
    """'http://login.paypal.com' -> 'paypal'."""
    return split(host_or_url)[1]


def is_ip(host):
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_reserved
        or ip.is_multicast or ip.is_link_local or ip.is_unspecified
    )


def address_domain(header_value):
    """Domain part of an address header such as 'Name <a@b.com>'."""
    if not header_value:
        return ""
    _, address = parseaddr(str(header_value))
    if "@" not in address:
        match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", str(header_value))
        return match.group(1).lower() if match else ""
    return address.rsplit("@", 1)[-1].lower().strip(" >")


def display_name(header_value):
    if not header_value:
        return ""
    value = str(header_value)
    name, _ = parseaddr(value)
    if not name and "<" in value:
        # parseaddr gives up on names containing commas ("Facebook, _ <x@y>").
        name = value.split("<", 1)[0]
    return name.strip().strip('"').strip()


def same_organisation(domain_a, domain_b):
    """True when two hosts share the same registered domain."""
    if not domain_a or not domain_b:
        return False
    return registered_domain(domain_a) == registered_domain(domain_b)


# ----------------------------------------------------------------------
# Look-alike (confusable) characters
# ----------------------------------------------------------------------

import unicodedata

# Common Cyrillic / Greek letters that look like Latin ones.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "г": "r", "п": "n", "т": "t", "к": "k", "м": "m", "н": "h", "в": "b",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "ν": "v", "ο": "o", "α": "a", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})

_LATIN_RE = re.compile(r"[A-Za-z]")
_CONFUSABLE_SET = set("аеорсухгіјѕԁɡһӏАВЕКМНОРСТХЅІЈνοαρτικΑΒΕΖΗΙΚΜΝΟΡΤΥΧ")


def normalize_text(text):
    """NFKC (turns 'math bold' 𝗬𝗼𝘂𝗿 into 'Your') + Cyrillic/Greek look-alikes."""
    return unicodedata.normalize("NFKC", text or "").translate(_CONFUSABLES)


def brand_skeleton(text):
    """Lower-case skeleton used to compare brand names: lCIoud -> icioud == icloud."""
    t = normalize_text(text).lower()
    return t.replace("rn", "m").replace("vv", "w").replace("1", "i").replace("l", "i").replace("0", "o")


def has_obfuscated_letters(text):
    """
    True when a word mixes Latin letters with look-alike Cyrillic/Greek ones,
    or the text uses 'mathematical' styled letters (U+1D400-U+1D7FF), both of
    which are used to slip past keyword filters.
    """
    if not text:
        return False
    if any(0x1D400 <= ord(ch) <= 0x1D7FF for ch in text):
        return True
    for word in re.findall(r"\w{3,}", text):
        if any(ch in _CONFUSABLE_SET for ch in word) and _LATIN_RE.search(word):
            return True
    return False
