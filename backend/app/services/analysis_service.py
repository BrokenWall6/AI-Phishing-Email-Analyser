from app.config import settings
from app.llm.llm_service import LLMService
from app.services import domain_utils
from app.services.analyzers.brand_mismatch_analyzer import BrandMismatchAnalyzer
from app.services.analyzers.content_analyzer import ContentAnalyzer
from app.services.analyzers.dns_analyzer import DNSAnalyzer
from app.services.analyzers.header_analyzer import HeaderAnalyzer
from app.services.analyzers.ioc_extractor import IOCExtractor
from app.services.analyzers.mitre_mapper import MitreMapper
from app.services.analyzers.threat_intelligence import ThreatIntelligence
from app.services.analyzers.whois_analyzer import WhoisAnalyzer
from app.services.attack_narrative_builder import AttackNarrativeBuilder
from app.services.email_parser import EmailParser
from app.services.evidence_builder import EvidenceBuilder
from app.services.trusted_domains import TrustedDomainFilter
from app.services.url_analyzer import URLAnalyzer
from app.services.url_extractor import URLExtractor
from app.services.verdict_engine import VerdictEngine


class AnalysisService:
    """
    Runs the full analysis of one .eml file.

    Order matters: header and content analysis run before the brand check,
    because the brand check needs to know whether the mail came from a
    mailing list and whether it asks for credentials. WHOIS and DNS run
    once per registered domain, for the most suspicious domains only.

    include_ai_report=False skips the LLM, which batch evaluation uses.
    """

    def __init__(self):
        self.parser = EmailParser()
        self.extractor = URLExtractor()
        self.url_analyzer = URLAnalyzer()
        self.whois_analyzer = WhoisAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.evidence_builder = EvidenceBuilder()
        self.verdict_engine = VerdictEngine()
        self.narrative_builder = AttackNarrativeBuilder()
        self.trusted_filter = TrustedDomainFilter()
        self.llm = LLMService()
        self.brand_analyzer = BrandMismatchAnalyzer()
        self.ioc_extractor = IOCExtractor()
        self.mitre_mapper = MitreMapper()
        self.threat_intelligence = ThreatIntelligence()

    def extract_domain(self, url):
        return domain_utils.registered_domain(url)

    def _domains_to_lookup(self, url_results):
        """Distinct, non-trusted registered domains, most suspicious first."""
        ranked = sorted(url_results, key=lambda r: r.get("risk_score", 0), reverse=True)
        domains = []
        for result in ranked:
            url = result["url"]
            if self.trusted_filter.is_trusted(url):
                continue
            domain = self.extract_domain(url)
            if domain and domain not in domains and not domain_utils.is_ip(domain):
                domains.append(domain)
        return domains[: settings.MAX_DOMAIN_LOOKUPS]

    def analyze_email(self, email_path, include_ai_report=None):

        if include_ai_report is None:
            include_ai_report = settings.ENABLE_AI_REPORT

        # 1. Parse
        email = self.parser.parse_email(email_path)

        # 2. IOCs
        email["ioc_analysis"] = self.ioc_extractor.analyze(email)

        # 3. URLs (text + HTML links)
        urls = self.extractor.extract_urls(email["body"], email.get("html_body", ""))
        email["url_analysis"] = [self.url_analyzer.analyze(url) for url in urls]

        # 4. Header analysis
        email["header_analysis"] = self.header_analyzer.analyze(email)

        # 5. Content / social-engineering analysis
        email["content_analysis"] = self.content_analyzer.analyze(email)

        # 6. Brand impersonation (uses header + content context)
        email["brand_analysis"] = self.brand_analyzer.analyze(
            email,
            urls,
            content_analysis=email["content_analysis"],
            mailing_list=email["header_analysis"].get("mailing_list", False),
        )

        # 7. WHOIS + DNS, once per registered domain
        lookup_domains = self._domains_to_lookup(email["url_analysis"])
        email["whois_analysis"] = [self.whois_analyzer.analyze(d) for d in lookup_domains]
        email["dns_analysis"] = [self.dns_analyzer.analyze(d) for d in lookup_domains]

        # 8. Threat intelligence
        email["threat_intelligence"] = self.threat_intelligence.analyze(email)

        # 9. Evidence + verdict (deterministic source of truth)
        evidence = self.evidence_builder.build(email)
        email["evidence"] = evidence

        verdict = self.verdict_engine.calculate(evidence)
        email["verdict"] = verdict

        # 10. Narrative + MITRE mapping
        email["attack_narrative"] = self.narrative_builder.build(email, evidence)
        email["mitre_attack"] = self.mitre_mapper.analyze(email)

        # 11. AI report (explanation only - never changes the verdict)
        if include_ai_report:
            email["ai_report"] = self.llm.analyze(
                evidence, verdict, mitre=email["mitre_attack"]
            )
        else:
            email["ai_report"] = {
                "status": "skipped",
                "summary": "AI report not requested.",
                "recommendations": [],
            }

        # The raw HTML can be large; the dashboard does not need it.
        email.pop("html_body", None)

        return email
