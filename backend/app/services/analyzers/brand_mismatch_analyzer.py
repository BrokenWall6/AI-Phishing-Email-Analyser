import re

from app.services import domain_utils


class BrandMismatchAnalyzer:
    """
    Detects brand impersonation.

    Strong case: the display name or subject claims a brand, but the sender
    domain does not belong to it. A brand mentioned only in the body, with
    links elsewhere, counts only when the mail also asks for credentials or
    threatens the account; otherwise it is just a note. Each brand is
    scored once.
    """

    # Brand -> keywords that identify it (matched on whole words, after
    # folding look-alike characters). Generic words are avoided on purpose
    # ("office", "meta", "chase", "ups" alone would match ordinary text).
    BRANDS = {
        "paypal": ["paypal"],
        "google": ["google", "gmail", "youtube"],
        "microsoft": ["microsoft", "office 365", "office365", "outlook.com", "hotmail", "onedrive", "sharepoint"],
        "amazon": ["amazon", "amazon prime"],
        "apple": ["apple id", "apple", "icloud", "itunes"],
        "facebook": ["facebook", "instagram", "whatsapp"],
        "netflix": ["netflix"],
        "linkedin": ["linkedin"],
        "dhl": ["dhl"],
        "fedex": ["fedex"],
        "usps": ["usps"],
        "royal mail": ["royal mail"],
        "postnl": ["postnl"],
        "correios": ["correios"],
        "bank of america": ["bank of america"],
        "chase": ["chase bank", "jpmorgan chase"],
        "wells fargo": ["wells fargo"],
        "bradesco": ["bradesco", "livelo"],
        "banco do brasil": ["banco do brasil"],
        "itau": ["itaú", "itau"],
        "santander": ["santander"],
        "ing": ["ing bank"],
        "coinbase": ["coinbase"],
        "binance": ["binance"],
        "kraken": ["kraken"],
        "metamask": ["metamask"],
        "trust wallet": ["trust wallet"],
        "ledger": ["ledger live", "ledger wallet", "ledger"],
        "exodus": ["exodus wallet", "exodus"],
        "mcafee": ["mcafee"],
        "norton": ["norton"],
        "docusign": ["docusign"],
        "dropbox": ["dropbox"],
        "adobe": ["adobe"],
        "spotify": ["spotify"],
        "sirius xm": ["sirius xm", "siriusxm"],
        "albert heijn": ["albert heijn", "albert-heijn"],
        "lidl": ["lidl"],
        "aldi": ["aldi"],
        "walmart": ["walmart"],
        "costco": ["costco"],
        "coca-cola": ["coca-cola", "coca cola"],
        "tesla": ["tesla"],
    }

    # Registered-domain labels that legitimately belong to each brand.
    BRAND_DOMAINS = {
        "paypal": {"paypal", "paypalobjects"},
        "google": {"google", "gmail", "youtube", "googlemail", "googleapis",
                   "gstatic", "googlegroups", "googleusercontent", "withgoogle"},
        "microsoft": {"microsoft", "office", "office365", "outlook", "live",
                      "hotmail", "microsoftonline", "onedrive", "msn", "windows", "sharepoint"},
        "amazon": {"amazon", "amazonaws", "amazonses", "a2z"},
        "apple": {"apple", "icloud", "me", "mac"},
        "facebook": {"facebook", "fb", "fbcdn", "instagram", "meta", "whatsapp", "facebookmail"},
        "netflix": {"netflix"},
        "linkedin": {"linkedin", "licdn"},
        "dhl": {"dhl"},
        "fedex": {"fedex"},
        "usps": {"usps"},
        "royal mail": {"royalmail"},
        "postnl": {"postnl"},
        "correios": {"correios"},
        "bank of america": {"bankofamerica", "bofa"},
        "chase": {"chase", "jpmorganchase"},
        "wells fargo": {"wellsfargo", "wf"},
        "bradesco": {"bradesco", "livelo"},
        "banco do brasil": {"bb"},
        "itau": {"itau"},
        "santander": {"santander"},
        "ing": {"ing"},
        "coinbase": {"coinbase"},
        "binance": {"binance"},
        "kraken": {"kraken"},
        "metamask": {"metamask"},
        "trust wallet": {"trustwallet"},
        "ledger": {"ledger"},
        "exodus": {"exodus"},
        "mcafee": {"mcafee"},
        "norton": {"norton", "nortonlifelock"},
        "docusign": {"docusign"},
        "dropbox": {"dropbox"},
        "adobe": {"adobe"},
        "spotify": {"spotify"},
        "sirius xm": {"siriusxm"},
        "albert heijn": {"ah", "albertheijn"},
        "lidl": {"lidl"},
        "aldi": {"aldi"},
        "walmart": {"walmart"},
        "costco": {"costco"},
        "coca-cola": {"coca-cola", "cocacola", "coke"},
        "tesla": {"tesla"},
    }

    # Infrastructure that is not a brand claim in itself.
    INFRASTRUCTURE = {
        "googleapis", "gstatic", "cloudflare", "amazonaws", "akamaihd",
        "githubusercontent", "jquery", "bootstrapcdn", "w3", "doubleclick",
    }

    def clean_html(self, text):
        if not text:
            return ""
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.lower().strip()

    def get_registered_domain(self, url):
        return domain_utils.domain_label(url)

    def get_sender_domain(self, email):
        return domain_utils.domain_label(domain_utils.address_domain(email.get("from", "")))

    def _brands_in(self, text):
        """Brands mentioned in text, robust to look-alikes (lCIoud -> icloud)."""
        skeleton = domain_utils.brand_skeleton(text)
        found = []
        for brand, keywords in self.BRANDS.items():
            for keyword in keywords:
                key = domain_utils.brand_skeleton(keyword)
                if re.search(r"(?<![a-z0-9])" + re.escape(key) + r"(?![a-z0-9])", skeleton):
                    found.append(brand)
                    break
        return found

    CLAIM_WORDS = r"(inc\.?|support|service|services|security|team|account|accounts|billing|customer|care|online|alert|alerts|notification|notifications|help|center|centre|id|verification|update|official|giveaway|gifts?|rewards?|prize|promo|promotions?|loyalty|program|membership|guthaben|gewinnspiel|cadeau\w*|prêmio|premio|principal|prime|wallet)"

    def _display_claims_brand(self, display, brand):
        """True if the display name is the brand itself, optionally + service words."""
        name = domain_utils.brand_skeleton(display).strip()
        words = domain_utils.brand_skeleton(self.CLAIM_WORDS)
        for keyword in self.BRANDS.get(brand, [brand]):
            key = re.escape(domain_utils.brand_skeleton(keyword))
            if re.match(rf"^[\W_]*{key}([\W_]+{words})*[\W_]*$", name):
                return True
            if re.match(rf"^[\W_]*{words}[\W_]+{key}[\W_]*$", name):
                return True
        return False

    def _belongs_to(self, brand, domain_label):
        return domain_label in self.BRAND_DOMAINS.get(brand, {brand})

    def analyze(self, email, urls, content_analysis=None, mailing_list=False):

        findings = []
        notes = []
        risk_score = 0

        sender_label = self.get_sender_domain(email)
        display = domain_utils.display_name(email.get("from", "")).lower()
        subject = (email.get("subject") or "").lower()
        body = self.clean_html(email.get("body", ""))

        content_analysis = content_analysis or {}
        indicators = content_analysis.get("indicators", {})
        credential_context = bool(
            indicators.get("credential_request") or indicators.get("account_threat")
        )
        # Any social-engineering pretext (prize, parcel, urgency) alongside a
        # brand-named sender is enough to treat the name as a claim.
        lure_context = credential_context or bool(
            indicators.get("financial_lure") or indicators.get("delivery_scam")
            or indicators.get("urgency") or indicators.get("address_greeting")
        )

        scored_brands = set()
        sender_claim = False

        # Sender claims to BE a brand but sends from an unrelated domain.
        # "PayPal" / "PayPal Security Team" counts; a newsletter named
        # "Lockergnome Apple Core" merely mentions a brand and does not.
        for brand in self._brands_in(display):
            if sender_label and not self._belongs_to(brand, sender_label):
                if self._display_claims_brand(display, brand) or lure_context:
                    findings.append(
                        f"The sender name claims to be '{brand}' but the email was sent "
                        f"from the unrelated domain '{sender_label}'."
                    )
                    scored_brands.add(brand)
                    sender_claim = True
                    risk_score += 35

        # Subject claims a brand (non-list mail) together with
        # credential / account-threat language.
        if credential_context and not mailing_list:
            for brand in self._brands_in(subject):
                if brand in scored_brands:
                    continue
                if sender_label and not self._belongs_to(brand, sender_label):
                    findings.append(
                        f"The subject references '{brand}' with an account/credential request, "
                        f"but the sender domain is '{sender_label}'."
                    )
                    scored_brands.add(brand)
                    sender_claim = True
                    risk_score += 35

        # Brand mentioned in the content while the links go elsewhere.
        body_brands = self._brands_in(f"{subject} {body}")
        link_labels = []
        for url in urls:
            label = self.get_registered_domain(url)
            if label and label not in self.INFRASTRUCTURE and label not in link_labels:
                link_labels.append(label)

        for brand in body_brands:

            if brand in scored_brands:
                continue

            if sender_label and self._belongs_to(brand, sender_label):
                continue

            unrelated = [l for l in link_labels if not self._belongs_to(brand, l)]
            if not unrelated or not link_labels:
                continue

            if any(self._belongs_to(brand, l) for l in link_labels) and len(unrelated) < len(link_labels) / 2:
                # Mostly links to the brand itself: normal.
                continue

            if credential_context:
                findings.append(
                    f"Brand '{brand}' is referenced alongside credential or account "
                    f"requests, but links point to unrelated domain '{unrelated[0]}'."
                )
                scored_brands.add(brand)
                risk_score += 35
            else:
                notes.append(
                    f"Brand '{brand}' is mentioned and links point to other domains "
                    f"(e.g. '{unrelated[0]}'); not scored without credential context."
                )

        return {
            "risk_score": min(risk_score, 70),
            "brands_detected": sorted(set(body_brands) | scored_brands),
            # display name or subject claims a brand the sender doesn't own
            "sender_claim": sender_claim,
            "findings": findings,
            "notes": notes,
        }
