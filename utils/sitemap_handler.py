import requests
from requests.adapters import HTTPAdapter
from usp.web_client.requests_client import RequestsWebClient
from usp.tree import sitemap_tree_for_homepage
from urllib.parse import urlparse
import re

class SitemapHandler:
    def __init__(self, logger, timeout_seconds=10):
        self.logger = logger
        self.web_client = self._make_usp_client(timeout_seconds)

    
    def _make_usp_client(self, timeout_seconds):
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=0)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        client = RequestsWebClient(session=session, wait=0.0, random_wait=False)
        client.set_timeout(timeout_seconds)
        return client

    def discover_and_filter_urls(self, base_url):
        """
        Use ultimate-sitemap-parser to auto-discover all sitemap URLs and filter them.
        """

        VDP_KEYWORDS = [
            # Abbreviations & teams
            "vdp", "psirt", "cert", "csirt", "vsrt", "vuln", "cve", "cvss",

            # Core terms
            "vulnerability", "vulnerability-disclosure", "vulnerability-policy", "coordinated-disclosure",
            "responsible-disclosure", "coordinated-vulnerability", "disclosure-policy",
            "security-policy", "security-advisories", "security-advisory",

            # Reporting actions
            "report-a-vulnerability", "report-vulnerability", "report-security", "report-issue",
            "security-contact", "contact-security", "security-report", "security-issue", "incident-report",
            "incident-response", "incident-coordination",

            # Security team & program
            "product-security", "security-team", "security-research", "cybersecurity",
            "penetration-testing", "pen-test", "red-team", "security-review",

            # Bug bounty programs
            "bugbounty", "bug-bounty", "bug_bounty", "bugreport", "bug-report", "bug_report",
            "security-rewards", "rewards-program", "vulnerability-reward", "security-incentive",

            # Disclosure programs/platforms
            "disclosure-program", "vulnerability-coordination", "coordinated-vulnerability-disclosure",
            "zero-day", "zeroday", "exploit-disclosure", "security-programs",

            # Legal/authorization
            "authorized-testing", "safe-harbor", "legal-safe-harbor", "testing-authorization",
            "testing-policy", "testing-guidelines", "scope-of-testing"
        ]

        relevant_urls = []

        try:
            if base_url == "bmw.at":
                return[]
            self.logger.info(f"Trying to discover sitemaps for: {base_url}")
            full_url = self._normalize_url(base_url)
            tree = sitemap_tree_for_homepage(full_url, web_client=self.web_client)

            if tree is None:
                self.logger.warning(f"No sitemap tree found for {base_url}")
                return []

            all_pages = list(tree.all_pages())
            self.logger.info(f"Discovered {len(all_pages)} pages in sitemap(s)")

            for page in all_pages:
                if any(keyword.lower() in page.url.lower() for keyword in VDP_KEYWORDS):
                    relevant_urls.append(page.url)
            self.logger.info(f"Filtered {len(relevant_urls)} relevant URLs from sitemap")
            filtered_urls = self._filter_disallowed_urls(relevant_urls)
            self.logger.info(f"Removed {len(relevant_urls) - len(filtered_urls)} disallowed URLs")
            return filtered_urls

        except Exception as e:
            self.logger.error(f"Failed to parse sitemap for {base_url}: {e}")
            return []
    

    def _filter_disallowed_urls(self, urls):
        """
        Remove URLs that match disallowed keywords, language-locales, or years (1990–2025) anywhere in the URL.
        """
        DISALLOWED_KEYWORDS = [
            # Careers / HR
            "career", "careers", "jobs", "job", "vacancy", "recruit",
            "stellenangebot", "karriere", "position", "openings", "hiring",
            "work-with-us", "jobportal", "employer",

            # News / Media / Content
            "news", "press", "media", "newsroom", "blog", "articles",
            "story", "stories", "answers",

            # Marketing / Events
            "event", "events", "webinar", "livestream", "concert", "gig",
            "festival", "presentation", "whitepaper", "infographics",
            "watch", "playlist", "gallery", "photostory", "episodes",
            "song", "remix", "video",

            # Corporate / Investor / ESG
            "investor", "finance", "annual-report", "company-reports",
            "csr", "sustainability", "sustainable", "esg", "climate",
            "environmental-report", "responsible-sourcing",
            "financial-disclosures",

            # Legal / Generic
            "privacy", "cookie","imprint",

            # Sitemap / Structural
            "sitemap", "site-map", "taxonomy", "discoveries", "new",
            "basics", "notes", "certificate", "certifi", "dealer-certs","landingpages"

            # Product / Supply / Sales
            "suppliers", "supply", "goods", "hazardous", "by-design",
            "forming", "location", "what-we-do",

            # Industry / Medical / Other
            "clinical", "efpia", "parenting",
        ]

        DISALLOWED_PATH_FRAGMENTS = [
            "/cn/", "/jp/", "/fr/", "/es/", "/it/", "/pt/", "/ko/",
            "/zh/", "/ru/", "/ar/", "/pl/", "/tr/", "/th/", "/sv/", "/da/", "/nl/"
        ]

        ALLOWED_LOCALES = {
            "de-at", "de-de", "en-us", "en-uk", "de-ch"
        }

        YEAR_PATTERN = re.compile(r"(19[9][0-9]|20[0-2][0-9]|2025)")

        filtered = []
        for url in urls:
            url_lc = url.lower()

            # Filter by keyword blacklist
            if any(bad in url_lc for bad in DISALLOWED_KEYWORDS):
                continue

            # Filter by disallowed path fragments
            if any(fragment in url_lc for fragment in DISALLOWED_PATH_FRAGMENTS):
                continue

            # Filter out disallowed locale patterns
            locale_matches = re.findall(r"/([a-z]{2,3}-[a-z]{2,3})/", url_lc)
            if locale_matches and not any(loc in ALLOWED_LOCALES for loc in locale_matches):
                continue

            # Filter out URLs containing a year from 1990 to 2025
            if YEAR_PATTERN.search(url_lc):
                continue

            filtered.append(url)
        return filtered
    
 
    def _normalize_url(self, base_url):
        """
        Ensure the URL starts with https:// or http://
        """
        if not base_url.startswith(("http://", "https://")):
            normalized = f"https://{base_url}/"
            self.logger.debug(f"Normalized base URL: {base_url} → {normalized}")
            return normalized
        return base_url