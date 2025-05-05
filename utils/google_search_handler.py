import requests
import time
from urllib.parse import urlsplit, urlunsplit, urlparse
import re

class GoogleSearchHandler:
    def __init__(self, api_key, cse_id, logger):
        self.api_key = api_key
        self.cse_id = cse_id
        self.logger = logger

    def search(self, base_url, company_name, keywords, num_results=5, wait_time=1, max_total_results=5):
        """
        Perform Google searches: site-specific VDP keywords + external bug bounty platform queries.
        Return up to `max_total_results` URLs filtered for VDP relevance.
        """
        search_url = "https://www.googleapis.com/customsearch/v1"
        all_results = set()

        # --- Site-specific VDP queries ---
        for keyword in keywords:
            query = f"site:{base_url} {keyword}"
            self.logger.info(f"Performing Google search for {company_name} with query: {query}")
            params = {
                "key": self.api_key,
                "cx": self.cse_id,
                "q": query,
                "num": num_results,
            }

            try:
                response = requests.get(search_url, params=params, timeout=10)
                response.raise_for_status()
                search_results = response.json()

                if "items" in search_results:
                    for item in search_results["items"]:
                        cleaned_url = self.clean_url(item["link"])
                        all_results.add(cleaned_url)
                        self.logger.info(f"Google search result found: {cleaned_url}")
                else:
                    self.logger.warning(f"No results found for query: {query}")

                time.sleep(wait_time)

            except requests.RequestException as e:
                self.logger.error(f"Error during Google search for {company_name} (query: {query}): {e}")
            except KeyError:
                self.logger.warning(f"No 'items' in Google search response for query: {query}")

        # --- External platform queries ---
        external_platforms = ["intigriti", "hackerone"]

        # Common legal suffixes (regex-safe, word-boundary matched)
        legal_suffixes = [
            r"\bAG\b", r"\bGmbH\b", r"\bSE\b", r"\bCo KG\b", r"\bInc\b",
            r"\bLLC\b", r"\bS\.A\.\b", r"\bLtd\b", r"\bPte Ltd\b", r"\bS\.r\.l\b", r"\bBV\b"
        ]

        # Clean company name by removing legal suffixes
        cleaned_company_name = company_name
        for suffix in legal_suffixes:
            cleaned_company_name = re.sub(suffix, "", cleaned_company_name, flags=re.IGNORECASE).strip()

        # Collapse double spaces left by removal
        cleaned_company_name = re.sub(r"\s{2,}", " ", cleaned_company_name)

        for platform in external_platforms:
            query = f"{cleaned_company_name} {platform}"
            self.logger.info(f"Performing external VDP search for {company_name} with query: {query}")
            params = {
                "key": self.api_key,
                "cx": self.cse_id,
                "q": query,
                "num": num_results,
            }

            try:
                response = requests.get(search_url, params=params, timeout=10)
                response.raise_for_status()
                search_results = response.json()

                if "items" in search_results:
                    for item in search_results["items"]:
                        cleaned_url = self.clean_url(item["link"])
                        all_results.add(cleaned_url)
                        self.logger.info(f"External platform result found: {cleaned_url}")
                else:
                    self.logger.warning(f"No results found for external query: {query}")

                time.sleep(wait_time)

            except requests.RequestException as e:
                self.logger.error(f"Error during external platform search for {company_name} (query: {query}): {e}")
            except KeyError:
                self.logger.warning(f"No 'items' in response for platform query: {query}")

        # --- Final filtering step ---
        filtered_urls = self.filter_vdp_urls(
            urls=list(all_results),
            base_domain=base_url,
            company_name=company_name
        )

        return filtered_urls[:max_total_results], "google"


    def filter_vdp_urls(self, urls, base_domain, company_name):
        """
        Filter URLs based on:
        - Domain match OR trusted external source + company in path
        - VDP-related keywords in URL
        Logs reasons for inclusion/exclusion.
        """
        VDP_KEYWORDS = [
            "vdp", "psirt", "cert", "security", "cybersecurity", "security-policy",
            "security-team", "security-contact", "product-security", "incident-response",
            "psirt-policy", "vulnerability", "vulnerability-policy", "coordinated-disclosure",
            "coordinated-vulnerability", "responsible-disclosure", "responsible-reporting",
            "bugbounty", "bug-bounty", "bug_report", "report-a-vulnerability",
            "report-security", "report-security-issue", "security-report", "security-advisories",
            "programs", "penetration-testing", "zero-day", "disclosure",
        ]

        # --- Reject if disallowed keywords appear ---
        DISALLOWED_KEYWORDS = [
            "career", "careers", "jobs", "job", "vacancy", "recruit",
            "stellenangebot", "karriere", "position", "openings", "hiring",
            "work-with-us", "jobportal", "news", "press", "media", "investor",
            "finance", "annual-report", "csr", "sustainability", "sustainable",
            "sitemap", "site-map", "taxonomy", "environmental-report", "company-reports",
            "sustainable-environmentally", "responsible-sourcing", "financial-disclosures",
            "climate", "eviroment", "esg", "cookie", "privacy", "blog", "music", "video"
        ]

        EXTERNAL_VDP_DOMAINS = ["intigriti.com", "hackerone.com"]

        def is_relevant(url):
            url_lc = url.lower()
            parsed = urlparse(url_lc)
            hostname = parsed.hostname or ""
            path = parsed.path or ""

            has_keyword = any(kw in url_lc for kw in VDP_KEYWORDS)
            base_match = base_domain in hostname
            external_match = any(d in hostname for d in EXTERNAL_VDP_DOMAINS)


            if any(bad in url_lc for bad in DISALLOWED_KEYWORDS):
                self.logger.info(f"✘ Filtering out URL {url}: matched disallowed keyword.")
                return False

            # --- Remove legal suffixes ---
            legal_suffixes = [
                r"\bAG\b", r"\bGmbH\b", r"\bSE\b", r"\bCo KG\b", r"\bInc\b",
                r"\bLLC\b", r"\bS\.A\.\b", r"\bLtd\b", r"\bPte Ltd\b", r"\bS\.r\.l\b", r"\bBV\b"
            ]
            cleaned_company = company_name
            for suffix in legal_suffixes:
                cleaned_company = re.sub(suffix, "", cleaned_company, flags=re.IGNORECASE).strip()

            # --- Split into keywords and clean them ---
            company_keywords = re.split(r"[\s\-_,.]", cleaned_company.lower())
            company_keywords = [w for w in company_keywords if len(w) > 2]

            # --- Flatten the path for fuzzy matching ---
            path_flat = re.sub(r"[\s\-_/]", "", path.lower())

            # Match if any word from company name is found in the squashed path
            company_in_path = any(word in path_flat for word in company_keywords)

            if base_match and has_keyword:
                self.logger.info(f"✔ Keeping internal URL {url} (matched base domain + keyword).")
                return True
            elif external_match and company_in_path:
                self.logger.info(f"✔ Keeping external URL {url} (matched external source + company word + keyword).")
                return True
            else:
                self.logger.info(f"✘ Filtering out URL {url}: "
                                f"{'no keyword match' if not has_keyword else ''} "
                                f"{'no base domain match' if not base_match else ''} "
                                f"{'no company match' if not company_in_path else ''} "
                                f"{'not trusted domain' if not external_match and not base_match else ''}")
                return False

        return [url for url in urls if is_relevant(url)]

    @staticmethod
    def clean_url(url):
        """
        Remove query parameters and fragments from the URL.
        """
        parsed = urlsplit(url)
        cleaned_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
        return cleaned_url