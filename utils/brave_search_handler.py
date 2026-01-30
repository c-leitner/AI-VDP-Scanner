import time
import re
import requests
from urllib.parse import urlsplit, urlunsplit, urlparse


class BraveSearchHandler:
    """
    Brave Search API-based search handler.

    - Uses X-Subscription-Token header authentication.
    - Collects URLs from Brave web search results.
    - Applies your VDP filtering logic.
    - Reorders so internal URLs come first and external platforms (Intigriti/HackerOne) last.
    - Canonicalizes external platform URLs to remove duplicates like /detail, /updates, etc.
    """

    BRAVE_WEB_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key, logger, country="AT", search_lang="en", ui_lang="en", timeout=15):
        self.api_key = api_key
        self.logger = logger
        self.country = country
        self.search_lang = search_lang
        self.ui_lang = ui_lang
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key,  # per Brave docs
        })

    def search(self, base_url, company_name, keywords, num_results=5, wait_time=1, max_total_results=5):
        all_results = set()

        # 1) site queries
        #site_queries = {f"site:{base_url} {kw}" for kw in keywords}

        # 2) company queries (high-signal VDP terms)
        vdp_terms = {
            "vulnerability disclosure",
            "vulnerability disclosure policy",
            "responsible disclosure",
            "report a vulnerability",
            "security vulnerability reporting",
            "PSIRT",
            "product security",
        }
        company_queries = {f"{company_name} {t}" for t in vdp_terms}

        # 3) external platform queries (precise)
        ext_queries = {
            f"{company_name} site:app.intigriti.com",
            f"{company_name} site:intigriti.com programs",
            f"{company_name} site:hackerone.com",
            f"{company_name} hackerone program",
        }

        first_token = (company_name.split()[0] if company_name else "").strip()
        if len(first_token) >= 3:
            ext_queries |= {
                f"{first_token} site:app.intigriti.com",
                f"{first_token} site:hackerone.com",
                f"{first_token} intigriti program",
                f"{first_token} hackerone program",
            }

        # Execute queries
        #for query in sorted(site_queries):
        #    self.logger.info(f"Performing Brave site search for {company_name} with query: {query}")
        #    self._run_query_into_set(query, all_results, max_results=num_results, wait_time=wait_time, log_prefix="site")

        for query in sorted(company_queries):
            self.logger.info(f"Performing Brave company search for {company_name} with query: {query}")
            self._run_query_into_set(query, all_results, max_results=num_results, wait_time=wait_time, log_prefix="company", info_on_hit=True)

        for query in sorted(ext_queries):
            self.logger.info(f"Performing Brave external search for {company_name} with query: {query}")
            self._run_query_into_set(query, all_results, max_results=num_results, wait_time=wait_time, log_prefix="external", info_on_hit=True)

        # Filter + canonicalize duplicates (intigriti program subpaths etc.)
        filtered = self.filter_vdp_urls(list(all_results), base_domain=base_url, company_name=company_name)

        # Reorder (internal first, platforms last)
        ordered = self.reorder_urls_internal_first(filtered)

        return ordered[:max_total_results], "brave"

    def _run_query_into_set(self, query, result_set, max_results, wait_time, log_prefix="", info_on_hit=False):
        try:
            links = self._brave_links(query, count=max_results)
            if not links:
                self.logger.debug(f"No Brave results returned for {log_prefix} query: {query}")
            for link in links:
                cleaned = self.clean_url(link)
                if cleaned not in result_set:
                    result_set.add(cleaned)
                    if info_on_hit:
                        self.logger.info(f"{log_prefix.capitalize()} result found: {cleaned}")
                    else:
                        self.logger.debug(f"{log_prefix.capitalize()} result found: {cleaned}")

            time.sleep(wait_time)

        except Exception as e:
            self.logger.error(f"Error during Brave {log_prefix} search (query: {query}): {e}")

    def _brave_links(self, query: str, count: int):
        """
        Calls Brave Web Search API and returns a list of result URLs.
        """
        params = {
            "q": query,
            "count": int(count),
            "country": self.country,
            "search_lang": self.search_lang,
            #"ui_lang": self.ui_lang,
            # you can add "safesearch": "moderate"/"strict"/"off" if needed (check docs)
        }

        # Basic retry/backoff for 429
        for attempt in range(1, 4):
            resp = self.session.get(self.BRAVE_WEB_ENDPOINT, params=params, timeout=self.timeout)

            if resp.status_code == 429:
                # exponential backoff
                sleep_s = min(2 ** attempt, 8)
                self.logger.warning(f"Brave rate limit (429) for query={query!r}. Backing off {sleep_s}s (attempt {attempt}/3).")
                time.sleep(sleep_s)
                continue

            resp.raise_for_status()
            data = resp.json()

            # Typical structure: data["web"]["results"] list of items with "url"
            web = data.get("web") or {}
            results = web.get("results") or []
            links = []
            for item in results:
                u = item.get("url") or item.get("link") or item.get("href")
                if u:
                    links.append(u)
            return links[:count]

        return []

    def reorder_urls_internal_first(self, urls):
        """
        Put Intigriti/HackerOne at the bottom so you can inspect internal URLs first.
        """
        external_domains = ["intigriti.com", "hackerone.com"]

        def is_external(u):
            host = urlparse(u.lower()).hostname or ""
            return any(d in host for d in external_domains)

        internal, external = [], []
        for u in urls:
            (external if is_external(u) else internal).append(u)
        return internal + external

    def canonicalize_external_url(self, url: str) -> str:
        """
        Collapse external VDP URLs to a canonical program URL to avoid duplicates:
          - Intigriti: https://app.intigriti.com/programs/<org>/<program>
          - HackerOne: https://hackerone.com/<program>
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""

        if "app.intigriti.com" in host:
            m = re.match(r"^/programs/[^/]+/[^/]+", path)
            if m:
                return f"{parsed.scheme}://{host}{m.group(0)}"

        if "hackerone.com" in host:
            m = re.match(r"^/[^/]+", path)
            if m:
                return f"{parsed.scheme}://{host}{m.group(0)}"

        return self.clean_url(url)

    def filter_vdp_urls(self, urls, base_domain, company_name):
        VDP_KEYWORDS = [
            "vdp", "psirt", "cert", "security", "cybersecurity", "security-policy",
            "security-team", "security-contact", "product-security", "incident-response",
            "psirt-policy", "vulnerability", "vulnerability-policy", "coordinated-disclosure",
            "coordinated-vulnerability", "responsible-disclosure", "responsible-reporting",
            "bugbounty", "bug-bounty", "bug_report", "report-a-vulnerability",
            "report-security", "report-security-issue", "security-report", "security-advisories",
            "programs", "penetration-testing", "zero-day", "disclosure",
        ]

        DISALLOWED_KEYWORDS = [
            "career", "careers", "jobs", "job", "vacancy", "recruit",
            "stellenangebot", "karriere", "position", "openings", "hiring",
            "work-with-us", "jobportal", "news", "press", "media", "investor",
            "finance", "annual-report", "csr", "sustainability", "sustainable",
            "sitemap", "site-map", "taxonomy", "environmental-report", "company-reports",
            "sustainable-environmentally", "responsible-sourcing", "financial-disclosures",
            "climate", "eviroment", "esg", "cookie", "privacy", "blog", "music", "video",
            "suppliers", "efpia", "clinical", "song", "episode", "remix", "security.txt"
        ]

        EXTERNAL_VDP_DOMAINS = ["intigriti.com", "hackerone.com"]

        def normalize_company_tokens(name: str):
            legal_suffixes = [
                r"\bAG\b", r"\bGmbH\b", r"\bSE\b", r"\bCo KG\b", r"\bInc\b",
                r"\bLLC\b", r"\bS\.A\.\b", r"\bLtd\b", r"\bPte Ltd\b", r"\bS\.r\.l\b", r"\bBV\b"
            ]

            original = (company_name or "").strip()
            cleaned = original
            for suffix in legal_suffixes:
                cleaned = re.sub(suffix, "", cleaned, flags=re.IGNORECASE).strip()
            cleaned = re.sub(r"\s{2,}", " ", cleaned)

            # Keep original capitalization info for acronyms
            raw_parts = re.split(r"[\s\-_,.]+", cleaned)
            strong_tokens = []
            acronyms = []

            for p in raw_parts:
                if not p:
                    continue
                if p.isupper() and 2 <= len(p) <= 5:
                    acronyms.append(p.lower())
                elif len(p) >= 5:
                    strong_tokens.append(p.lower())

            return strong_tokens, acronyms


        def hostname_matches_company(hostname: str, company: str):
            hn = (hostname or "").lower()
            labels = [lbl for lbl in re.split(r"[.\-]", hn) if lbl]  # split on . and -
            strong_tokens, acronyms = normalize_company_tokens(company_name)

            strong_hits = sum(1 for t in strong_tokens if any(lbl == t for lbl in labels))
            # also allow label contains token only if token is long enough and is a clear boundary-like match
            strong_hits += sum(1 for t in strong_tokens if any(lbl.startswith(t) or lbl.endswith(t) for lbl in labels))

            acronym_hits = sum(1 for a in acronyms if any(lbl == a for lbl in labels))

            # Rules:
            # - if we have 2 strong hits => definitely
            if strong_hits >= 2:
                return True
            # - if we have 1 strong hit and company has only one meaningful token => allow
            if strong_hits == 1 and len(strong_tokens) == 1:
                return True
            # - acronym alone is too weak unless it matches as a full label (already ensured) AND no strong tokens exist
            if acronym_hits >= 1 and len(strong_tokens) == 0:
                return True

            return False

        def company_words_in_path(path: str, company_name: str):
            strong_tokens, acronyms = normalize_company_tokens(company_name)
            p = (path or "").lower()

            # word-ish boundaries in path: split on non-letters/numbers
            parts = [x for x in re.split(r"[^a-z0-9]+", p) if x]

            strong_hit = any(t in parts for t in strong_tokens)
            acronym_hit = any(a in parts for a in acronyms)

            # Prefer strong hit; acronym hit alone is weak
            return strong_hit or (acronym_hit and not strong_tokens)
        
        def is_relevant(url):
            url_lc = url.lower()
            parsed = urlparse(url_lc)
            hostname = parsed.hostname or ""
            path = parsed.path or ""

            if any(bad in url_lc for bad in DISALLOWED_KEYWORDS):
                return False

            has_keyword = any(kw in url_lc for kw in VDP_KEYWORDS)

            base_match = (base_domain in hostname) if base_domain else False
            company_host_match = hostname_matches_company(hostname, company_name)

            external_match = any(d in hostname for d in EXTERNAL_VDP_DOMAINS)
            company_in_path = company_words_in_path(path, company_name)

            if (base_match or company_host_match) and has_keyword:
                return True

            if external_match and company_in_path and has_keyword:
                return True

            return False

        # Filter + canonicalize + dedupe
        seen = set()
        out = []
        for u in urls:
            if not is_relevant(u):
                continue
            canon = self.canonicalize_external_url(u)
            if canon in seen:
                continue
            seen.add(canon)
            out.append(canon)
        return out

    @staticmethod
    def clean_url(url):
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
