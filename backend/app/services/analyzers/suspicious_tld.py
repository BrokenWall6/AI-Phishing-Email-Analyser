import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


class SuspiciousTLDAnalyzer:
    """TLDs that are disproportionately used for abuse (cheap / free)."""

    SUSPICIOUS_TLDS = {
        "xyz", "top", "click", "live", "site", "online", "tk", "ml", "ga",
        "cf", "gq", "work", "loan", "zip", "mov", "icu", "buzz", "rest",
        "cam", "monster", "country", "kim", "men", "date", "racing", "win",
    }

    def analyze(self, url):

        findings = []
        score = 0

        tld = (_EXTRACT(url).suffix or "").lower()

        # Only look at the last label so "xyz" also matches e.g. "co.xyz".
        last_label = tld.rsplit(".", 1)[-1]

        if last_label in self.SUSPICIOUS_TLDS:
            findings.append("Suspicious TLD")
            score += 15

        return score, findings
