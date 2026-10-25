import re
from urllib.parse import urlparse

from app.services import domain_utils


class ContentAnalyzer:
    """
    Social-engineering indicators in the email text and HTML.

    Catches scams that have no suspicious link, such as "reply with your
    bank details". Each category is counted once so long emails cannot pile
    up points.

    Categories:
      - credential / personal data request
      - account threat (suspended, locked, unauthorized access ...)
      - urgency / pressure (needs 2+ distinct phrases)
      - financial lure / scam language (needs 2+ distinct phrases)
      - deceptive HTML links (visible URL differs from the real target)
      - HTML forms inside the email
      - shouting (mostly upper-case text, many exclamation marks)
    """

    CREDENTIAL_PATTERNS = [
        r"verify (your|the) (account|identity|information|details|email)",
        r"confirm (your|the) (account|identity|password|billing|payment|details|information)",
        r"update (your|the) (account|billing|payment|banking) (information|details)",
        r"(enter|provide|send|reply with) (your )?(password|pin|login|credentials)",
        r"(social security|ssn|national insurance) number",
        r"(credit|debit) card (number|details|information)",
        r"bank (account|routing) (number|information|details)",
        r"re-?activate your account",
        r"(payment|billing|card) (details|information) (are |is )?(required|needed|missing|outdated)",
        r"update (your )?(payment|billing) (method|details|information)",
        r"(identificeer|identificeren|identificatie)",
        # crypto wallets
        r"(seed|recovery|secret|mnemonic) phrase",
        r"private key",
        r"wallet (verification|validation|synchroni[sz]ation)",
        r"(verify|validate|connect|synchroni[sz]e) (your )?wallet",
        # German / Dutch / French / Portuguese / Spanish
        r"(verifizieren|bestätigen) sie (ihr|ihre|ihren)",
        r"(verifieer|bevestig|controleer) (uw|je|jouw) (account|gegevens|identiteit)",
        r"(vérifiez|confirmez|mettez à jour) (votre|vos)",
        r"(verifique|confirme|atualize) (sua|seu|seus|suas) (conta|dados|cadastro|identidade)",
        r"(verifique|confirme|actualice) (su|sus) (cuenta|datos|identidad)",
    ]

    ACCOUNT_THREAT_PATTERNS = [
        r"account (has been|will be|is) (suspended|locked|disabled|closed|terminated|limited|restricted|on hold)",
        r"unauthori[sz]ed (access|activity|login|transaction|charge)",
        r"(suspicious|unusual) (activity|sign-?in|login)",
        r"failure to (verify|confirm|respond|update)",
        r"(password|account) (will expire|has expired|expires (today|soon|in \d))",
        r"(wallet|membership|subscription|account|balance)\W+(?:\w+\W+){0,4}(has been |will be |is |was )?(suspended|locked|blocked|expired|cancell?ed|deactivated|deleted|closed)",
        r"(payment|renewal) (has )?(failed|declined|was failed)",
        r"(konto|account) (wurde|wird) (gesperrt|eingeschränkt|deaktiviert)",
        r"(account|rekening) (is|wordt) (geblokkeerd|opgeschort)",
        r"(compte|carte) (a été |sera )?(suspendu|bloqué|désactivé)",
        r"(conta|cartão|cpf) (foi |será )?(bloquead|suspens|cancelad)",
    ]

    URGENCY_PATTERNS = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"within (24|48|72) hours",
        r"\bact now\b",
        r"limited time",
        r"expires? (today|soon|tomorrow)",
        r"final (notice|warning|reminder)",
        r"don'?t (delay|wait|miss)",
        r"\btoday only\b",
        r"respond (now|immediately|promptly)",
        r"\bhurry\b",
        r"while supplies last",
        r"(offer|deal) ends",
        r"last chance",
        r"(sofort|umgehend|dringend|letzte (chance|mahnung|erinnerung))",
        r"(direct|onmiddellijk|dringend|laatste (kans|herinnering))",
        r"(immédiatement|urgent|dernière (chance|relance))",
        r"(imediatamente|urgente|última (chance|oportunidade)|prazo final)",
        r"(inmediatamente|última oportunidad)",
    ]

    FINANCIAL_LURE_PATTERNS = [
        r"you (have )?(won|been selected)",
        r"\bwinner\b",
        r"\blottery\b",
        r"claim your (prize|reward|refund|money)",
        r"\$\s?\d[\d,]*(\.\d+)? (per|a) (week|day|month)",
        r"(make|earn|making|earning) (\$|money|cash|\d)",
        r"(million|thousand) (dollars|usd|us\$)",
        r"100% (free|guaranteed|risk[- ]free)",
        r"\brisk[- ]free\b",
        r"no (cost|obligation|risk)",
        r"(work|working) from home",
        r"double your",
        r"wire transfer",
        r"\binheritance\b",
        r"\bbeneficiary\b",
        r"cash (flow|bonus|prize)",
        r"financial freedom",
        r"(lowest|best) (rates?|price)",
        r"\bfree (gift|trial|offer|money|cash|cd|sample)",
        r"money[- ]back guarantee",
        r"(cheap|discount) (meds|pills|viagra|software)",
        r"(credit|debt) (repair|consolidation|relief)",
        r"(mlm|multi[- ]level marketing|gifting program)",
        r"\bguaranteed\b",
        r"(click|reply) (here|below) to (claim|order|buy|get|receive|start)",
        r"save (up to )?\d+ ?%",
        r"(lowest|low) (rates?|prices?|cost)",
        r"free (quote|consultation|access|information|report)",
        r"no experience (is )?(required|necessary)",
        r"(be your own boss|extra income|excellent income|residual income)",
        r"lose \d+(-\d+)? ?(lbs|pounds|kg)",
        r"(order|call|buy) (now|today)",
        r"special (offer|promotion)",
        r"satisfaction guaranteed",
        r"(toll[- ]free|1-800-)",
        r"free spins?",
        r"no deposit",
        r"(welcome|casino|deposit|sign[- ]?up) bonus",
        r"\bairdrop\b",
        r"\bpresale\b",
        r"(claim|mint) (your|now|for free)",
        r"(gift ?card|voucher|reward) (is )?(waiting|ready|inside)",
        r"you('ve| have) been (chosen|selected)",
        r"(freispiele|gewinnspiel|gewinnen sie|kostenlos|gratis|herzlichen glückwunsch)",
        r"(gefeliciteerd|je bent geselecteerd|win (een|vandaag)|cadeaukaart|gratis)",
        r"(félicitations|gagnez|cadeau gratuit|bon d.achat)",
        r"(parabéns|grátis|prêmio|você foi selecionad)",
    ]

    # Parcel-delivery and fine/tax scams ("your package is held", "customs fee").
    DELIVERY_PATTERNS = [
        r"(package|parcel|shipment|delivery) (is )?(on hold|held|pending|suspended|could not be delivered)",
        r"(customs|delivery|redelivery|shipping) fee",
        r"(paket|sendung) .{0,30}(zugestellt|angehalten|zoll)",
        r"(pakket|zending) .{0,30}(bezorgd|tegengehouden|douane)",
        r"(colis|livraison) .{0,30}(en attente|bloqué|douane)",
        r"(mercadoria|encomenda|pedido) (retida|retido|taxad)",
        r"(multa|débito|pedágio|imposto) .{0,30}(pendente|regularize|prazo)",
    ]

    # Classic unsolicited bulk-mail markers (only scored for non-list mail;
    # real mailing lists also contain unsubscribe text).
    BULK_PATTERNS = [
        r"to (be|get) removed",
        r"remove (your|my) (address|name|e-?mail)",
        r"(wish|want|like) to (be removed|leave this list|unsubscribe|opt[- ]out)",
        r"no longer (wish|want|like) to (receive|get|be contacted)",
        r"(click|go) here to (be )?(removed|unsubscribe|opt[- ]out)",
        r"you (are receiving|received) this (e-?mail|message) because",
        r"this (is not|isn't) (spam|unsolicited)",
        r"sent in compliance with",
        r"one[- ]time (mailing|e-?mail)",
        r"opt[- ]?in list",
    ]

    ADULT_PATTERNS = [
        r"\bporn", r"\bxxx\b", r"\bnude\b", r"\bsluts?\b", r"\bhorny\b",
        r"\bviagra\b", r"\bmilf", r"penis|penile", r"\berotic\b", r"\bteens? (sex|nude|xxx)",
    ]

    MAX_SCORE = 50

    def analyze(self, email):

        subject = email.get("subject") or ""
        body = email.get("body") or ""
        html_body = email.get("html_body") or ""

        # NFKC + look-alike folding so "𝗩𝗲𝗿𝗶𝗳𝘆" and "Vеrify" (Cyrillic е) match too.
        text = domain_utils.normalize_text(f"{subject}\n{body}").lower()
        text = re.sub(r"\s+", " ", text)

        findings = []
        indicators = {}
        score = 0

        # Credential / personal data request
        credential_hits = self._hits(self.CREDENTIAL_PATTERNS, text)
        if credential_hits:
            indicators["credential_request"] = credential_hits
            findings.append("Email asks the recipient to provide or verify credentials or personal data.")
            score += 20

        # Account threat
        threat_hits = self._hits(self.ACCOUNT_THREAT_PATTERNS, text)
        if threat_hits:
            indicators["account_threat"] = threat_hits
            findings.append("Email threatens account suspension or reports unauthorized activity.")
            score += 15

        # Urgency (needs at least two different phrases)
        urgency_hits = self._hits(self.URGENCY_PATTERNS, text)
        if len(urgency_hits) >= 2:
            indicators["urgency"] = urgency_hits
            findings.append("Email uses multiple urgency or pressure tactics.")
            score += 10

        # Financial lure / scam language
        lure_hits = self._hits(self.FINANCIAL_LURE_PATTERNS, text)
        if len(lure_hits) >= 4:
            indicators["financial_lure"] = lure_hits
            findings.append("Email contains strong financial-lure or scam language.")
            score += 25
        elif len(lure_hits) >= 2:
            indicators["financial_lure"] = lure_hits
            findings.append("Email contains financial-lure or scam language.")
            score += 15

        # Parcel / fine / tax scams
        delivery_hits = self._hits(self.DELIVERY_PATTERNS, text)
        if delivery_hits:
            indicators["delivery_scam"] = delivery_hits
            findings.append("Email uses a parcel-delivery, fine or tax-payment pretext.")
            score += 15

        # Greets the recipient by their email address ("Hi bob@example.com",
        # or "bob@example.com, ..." in the subject), typical of bulk phishing.
        address = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
        greeting = re.search(
            rf"^\W*(hi|hello|dear|hey|hallo|hoi|beste|bonjour|olá|ola|hola|cher|liebe[r]?)?\W*{address}",
            domain_utils.normalize_text(body).strip()[:200], re.I)
        if re.search(address, subject) or greeting:
            indicators["address_greeting"] = True
            findings.append("Email addresses the recipient by their email address instead of a name.")
            score += 15

        # Look-alike letters in the subject or sender name
        if domain_utils.has_obfuscated_letters(f"{subject} {email.get('from') or ''}"):
            indicators["obfuscated_text"] = True
            findings.append("Subject or sender name uses look-alike or stylised characters to evade filters.")
            score += 20

        # Unsolicited bulk mail markers (not for mailing lists)
        is_list = bool(email.get("list_id") or email.get("list_unsubscribe")
                       or (email.get("precedence") or "").lower() in {"list", "bulk"})
        bulk_hits = self._hits(self.BULK_PATTERNS, text)
        subject_lower = subject.strip().lower()
        if subject_lower.startswith(("adv:", "adv ", "[adv]", "ad:")):
            bulk_hits.append("ADV subject tag")
        if bulk_hits and not is_list:
            indicators["bulk_mail"] = bulk_hits
            findings.append("Unsolicited bulk-mail markers (removal / opt-out instructions) in non-list mail.")
            score += 15

        # Adult content
        adult_hits = self._hits(self.ADULT_PATTERNS, text)
        if len(adult_hits) >= 2:
            indicators["adult_content"] = adult_hits
            findings.append("Email contains adult-content spam language.")
            score += 20

        # Same link repeated many times in a short, non-list email
        # (typical of ad blasts; newsletters repeat links too, so
        # only count when there are very few distinct links).
        links = [
            l for l in re.findall(r"https?://[^\s<>\"']+", f"{body} {html_body}")
            if not re.search(r"\.(gif|jpe?g|png|css|js)(\?|$)", l, re.I)
        ]
        if links and not is_list and len(set(links)) <= 3:
            most_common = max(set(links), key=links.count)
            if links.count(most_common) >= 4:
                indicators["repeated_link"] = most_common
                findings.append("The same link is repeated many times.")
                score += 10

        # Deceptive links: <a href="http://evil.xyz">http://paypal.com</a>
        deceptive = self._deceptive_links(html_body)
        if deceptive:
            indicators["deceptive_links"] = deceptive[:5]
            strongest = max(d["weight"] for d in deceptive)
            if strongest > 0:
                findings.append("Visible link text shows a different web address than the real link target.")
                score += strongest
            # Bare-domain text pointing at a tracking/redirect host is common in
            # legitimate newsletters, so it is recorded but not scored.

        # Forms inside the email (credential harvesting)
        if re.search(r"<\s*form\b", html_body, re.I):
            if re.search(r"type\s*=\s*[\"']?password", html_body, re.I):
                findings.append("Email contains an embedded form with a password field.")
                score += 30
            else:
                # Newsletters often embed search/subscribe forms: note only.
                indicators["html_form"] = True

        # Shouting
        letters = re.findall(r"[A-Za-z]", f"{subject} {body}")
        if len(letters) >= 200:
            upper_ratio = sum(c.isupper() for c in letters) / len(letters)
            if upper_ratio > 0.35:
                indicators["upper_case_ratio"] = round(upper_ratio, 2)
                findings.append("Large parts of the email are written in capital letters.")
                score += 10

        if len(re.findall(r"!{2,}", f"{subject} {body}")) >= 3:
            findings.append("Excessive use of exclamation marks.")
            score += 5

        return {
            "risk_score": min(score, self.MAX_SCORE),
            "findings": findings,
            "indicators": indicators,
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _hits(patterns, text):
        hits = []
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                hits.append(match.group(0))
        return hits

    @staticmethod
    def _deceptive_links(html_body):

        if not html_body:
            return []

        results = []

        for href, inner in re.findall(
            r'(?is)<a\s[^>]*href\s*=\s*["\']?([^"\'\s>]+)["\']?[^>]*>(.*?)</a>',
            html_body,
        ):
            visible = re.sub(r"(?s)<[^>]+>", "", inner).strip()

            shown = re.search(
                r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/\S*)?$",
                visible.lower(),
            )
            if not shown or not href.lower().startswith("http"):
                continue

            try:
                target_host = urlparse(href).hostname or ""
            except ValueError:
                continue

            shown_domain = domain_utils.registered_domain(shown.group(1))
            target_domain = domain_utils.registered_domain(target_host) or target_host

            if shown_domain and target_domain and shown_domain != target_domain:
                # Weight: a full URL shown as text, or an IP target, is the
                # classic phishing trick; a bare domain name is weak.
                explicit_url = visible.lower().startswith(("http://", "https://"))
                weight = 30 if domain_utils.is_ip(target_host) else (25 if explicit_url else 0)
                results.append({"shown": shown_domain, "actual": target_domain, "weight": weight})

        return results
