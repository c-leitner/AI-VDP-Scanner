import time
import re
import requests
from urllib.parse import urlsplit, urlunsplit, urlparse


class BraveSearchHandler:
    """
    Brave Search API-based search handler.
    """

    BRAVE_WEB_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key, logger, country="AT", search_lang="en", timeout=15):
        self.api_key = api_key
        self.logger = logger
        self.country = country
        self.search_lang = search_lang
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key,
        })

        # External whitelist: only these external domains survive if not base_host
        self.WHITELIST_DOMAINS = {
            "responsibledisclosure.com",
            "synack.com",
            "hackerone.com",
            "bugcrowd.com",
            "bughunters.google.com",
            "intigriti.com",
            "app.intigriti.com",

            # Common extras (program listings / aggregators)
            "yeswehack.com",
            "openbugbounty.org",
            # Optional corp/group domains (example)
            "bmwgroup.com",
        }

        # For platform path sanity (reduce noise within whitelisted domains)
        # Note: all entries are FIRST path segment only.
        self.H1_DISALLOWED_FIRST_SEGMENTS = {
            "reports",
            "hackers",
            "leaders",
            "blog",
            "events",
            "press",
            "resources",
            "policy_versions",
            "disclosure-guidelines",
            "customer-story",
            "organizations",
            "trust",
            "en",
            "knowledge-center",
            "bug-bounty-programs",
            "sign_up",
            "product",
            "healthcare",
            "customers",
            "pricing",
            "platform",
            "solutions",
            "partners",
            "about",
            "contact",
            "careers",
            "directory",
        }

        # Generic org tokens that cause false ownership matches (e.g., "bank")
        self.GENERIC_ORG_TOKENS = {
            "bank", "group", "company", "co", "corp", "corporation",
            "inc", "ltd", "llc", "gmbh", "ag", "sa", "bv", "se",
            "holding", "holdings",
            "services", "service", "financial", "finance",
            "international", "global",
            "systems", "system", "solutions", "solution",
            "technology", "technologies",
            "digital", "security"
        }

        # Bugcrowd non-program first segments (directory/marketing/etc.)
        self.BUGCROWD_DISALLOWED_FIRST_SEGMENTS = {
            "engagements",  # root is blocked explicitly; /engagements/<slug> is allowed
            "programs",
            "crowdstream",
            "customers",
            "blog",
            "resources",
            "about",
            "contact",
            "pricing",
            "support",
            "events",
        }

    # -------------------------------
    # Public API
    # -------------------------------

    def search(
        self,
        base_url,
        company_name,
        keywords,
        num_results=5,
        wait_time=1,
        max_total_results=5,
        max_total_results_returned=10
    ):
        """
        Returns (ordered_urls, "brave")
        """
        base_host = self._normalize_base_host(base_url)
        all_results = set()

        # Company queries (high-signal VDP terms)
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

        # External platform queries (precise)
        ext_queries = {
            f"{company_name} site:app.intigriti.com",
            f"{company_name} site:intigriti.com programs",
            f"{company_name} site:hackerone.com",
            f"{company_name} hackerone program",
            f"{company_name} site:bugcrowd.com",
            f"{company_name} bugcrowd program",
            f"{company_name} site:responsibledisclosure.com",
            f"{company_name} site:synack.com",
        }

        # For short names like "ups", also try the first token; helps discovery
        first_token = (company_name.split()[0] if company_name else "").strip()
        if len(first_token) >= 2:
            ext_queries |= {
                f"{first_token} site:app.intigriti.com",
                f"{first_token} site:hackerone.com",
                f"{first_token} intigriti program",
                f"{first_token} hackerone program",
                f"{first_token} site:bugcrowd.com",
                f"{first_token} site:responsibledisclosure.com",
            }

        # Execute queries
        for query in sorted(company_queries):
            self.logger.info(f"Performing Brave company search for {company_name} with query: {query}")
            self._run_query_into_set(
                query, all_results,
                max_results=num_results, wait_time=wait_time,
                log_prefix="company", info_on_hit=True
            )

        for query in sorted(ext_queries):
            self.logger.info(f"Performing Brave external search for {company_name} with query: {query}")
            self._run_query_into_set(
                query, all_results,
                max_results=num_results, wait_time=wait_time,
                log_prefix="external", info_on_hit=True
            )

        # 1) VDP filter FIRST (includes canonicalize + dedupe)
        filtered = self.filter_vdp_urls(list(all_results), base_host=base_host, company_name=company_name)

        # 2) Enforce "base_host OR whitelist domains"
        strict = self.keep_only_base_or_whitelist(filtered, base_host=base_host)

        # 3) Reorder base_host URLs first
        ordered = self.reorder_urls_internal_first(strict, base_host=base_host)

        self.logger.info(f"List of filtered matches: {ordered}")
        return (ordered[:max_total_results_returned] if max_total_results_returned else ordered), "brave"

    # -------------------------------
    # Brave API plumbing
    # -------------------------------

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
        params = {
            "q": query,
            "count": int(count),
            "country": self.country,
            "search_lang": self.search_lang,
        }

        for attempt in range(1, 4):
            resp = self.session.get(self.BRAVE_WEB_ENDPOINT, params=params, timeout=self.timeout)

            if resp.status_code == 429:
                sleep_s = min(2 ** attempt, 8)
                self.logger.warning(
                    f"Brave rate limit (429) for query={query!r}. Backing off {sleep_s}s (attempt {attempt}/3)."
                )
                time.sleep(sleep_s)
                continue

            if resp.status_code == 422:
                # Useful when Brave rejects parameters / query
                self.logger.error(f"Brave 422 for query={query!r}: {resp.text}")

            resp.raise_for_status()
            data = resp.json()

            web = data.get("web") or {}
            results = web.get("results") or []
            links = []
            for item in results:
                u = item.get("url") or item.get("link") or item.get("href")
                if u:
                    links.append(u)
            return links[:count]

        return []

    # -------------------------------
    # Strict domain rules
    # -------------------------------

    def _normalize_base_host(self, base_domain: str) -> str:
        """
        base_domain may be 'ups.com' or 'https://ups.com' or 'www.ups.com'.
        Normalize to 'ups.com'.
        """
        if not base_domain:
            return ""
        bd = base_domain.strip().lower()
        if "://" not in bd:
            bd = "https://" + bd
        host = urlparse(bd).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host

    def _host_matches_base(self, host: str, base_host: str) -> bool:
        """
        Exact host match or subdomain match.
        """
        host = (host or "").lower()
        base_host = (base_host or "").lower()
        if not host or not base_host:
            return False
        if host.startswith("www."):
            host = host[4:]
        return host == base_host or host.endswith("." + base_host)

    def _host_is_whitelisted(self, host: str) -> bool:
        """
        True if host equals a whitelisted domain OR is a subdomain of one.
        """
        host = (host or "").lower()
        if host.startswith("www."):
            host = host[4:]
        for d in self.WHITELIST_DOMAINS:
            d = d.lower()
            if host == d or host.endswith("." + d):
                return True
        return False

    def keep_only_base_or_whitelist(self, urls, base_host: str):
        """
        Keep URL if:
          - hostname matches base_host (exact/subdomain), OR
          - hostname is whitelisted (exact/subdomain)
        Everything else is dropped.
        """
        kept = []
        dropped = 0

        for u in urls:
            host = (urlparse(u).hostname or "").lower()
            if not host:
                continue

            if self._host_matches_base(host, base_host):
                kept.append(u)
                continue

            if self._host_is_whitelisted(host):
                kept.append(u)
                continue

            dropped += 1
            self.logger.debug(f"Dropping non-base/non-whitelist URL: {u}")

        if dropped:
            self.logger.info(f"Dropped {dropped} URLs not matching base_host or whitelist.")
        return kept

    def reorder_urls_internal_first(self, urls, base_host: str):
        """
        Internal means: hostname matches base_host.
        External means: anything else (but already whitelisted).
        """
        internal, external = [], []
        for u in urls:
            host = (urlparse(u).hostname or "").lower()
            if self._host_matches_base(host, base_host):
                internal.append(u)
            else:
                external.append(u)
        return internal + external

    # -------------------------------
    # Canonicalize external duplicates
    # -------------------------------

    def canonicalize_external_url(self, url: str) -> str:
        """
        Collapse external VDP URLs to canonical program URL to avoid duplicates:
          - Intigriti: https://app.intigriti.com/programs/<org>/<program>
          - HackerOne: https://hackerone.com/<program>
          - Bugcrowd: https://bugcrowd.com/engagements/<slug> or https://bugcrowd.com/<slug>
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        if "app.intigriti.com" in host:
            m = re.match(r"^/programs/[^/]+/[^/]+", path)
            if m:
                return f"{parsed.scheme}://{host}{m.group(0)}"

        if "hackerone.com" in host:
            m = re.match(r"^/[^/]+", path)
            if m:
                return f"{parsed.scheme}://{host}{m.group(0)}"

        if "bugcrowd.com" in host:
            # Keep /engagements/<slug> if present; otherwise keep first segment.
            p = (path or "").strip("/")

            m = re.match(r"^(engagements/[^/]+)", p, flags=re.IGNORECASE)
            if m:
                return f"{parsed.scheme}://{host}/{m.group(1)}"

            m = re.match(r"^([^/]+)", p)
            if m:
                return f"{parsed.scheme}://{host}/{m.group(1)}"

        return self.clean_url(url)

    def _external_platform_path_ok(self, hostname: str, path: str) -> bool:
        """
        Reduce noise on whitelisted platforms.
        """
        host = (hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        p = (path or "").strip("/")

        if "hackerone.com" in host:
            first = p.split("/")[0] if p else ""
            if not first:
                return False
            if first in self.H1_DISALLOWED_FIRST_SEGMENTS:
                return False
            return True

        if "app.intigriti.com" in host:
            return p.startswith("programs/")

        if "synack.com" in host:
            # allow /vdp/<company>/...
            p_lc = p.lower()
            if p_lc == "vdp":
                return False
            return p_lc.startswith("vdp/") and len(p_lc.split("/")) >= 2 and bool(p_lc.split("/")[1])

        # ResponsibleDisclosure subdomains are ok (fetch may be blocked later)
        if host.endswith("responsibledisclosure.com"):
            return True

        if "bugcrowd.com" in host:
            p_lc = p.lower()

            # Block directory roots explicitly (these are never programs)
            if p_lc in {"engagements", "programs", "crowdstream", "customers"}:
                return False

            # Allow only /engagements/<slug-or-id>/...
            if p_lc.startswith("engagements/"):
                parts = p_lc.split("/")
                return len(parts) >= 2 and bool(parts[1])

            # Allow direct program slugs: /<slug>, but reject known non-program sections
            first = p_lc.split("/")[0] if p_lc else ""
            if not first:
                return False
            if first in self.BUGCROWD_DISALLOWED_FIRST_SEGMENTS:
                return False

            return True

        return True

    # -------------------------------
    # VDP filtering
    # -------------------------------

    def filter_vdp_urls(self, urls, base_host: str, company_name: str):
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
            "suppliers", "efpia", "clinical", "song", "episode", "remix",
            "security.txt", "communications",
            "customer", "care", "faqs", "faq", "consumer", "merchant", "deposit", "volume",
            "report-suspicious-communications","how-tos"
        ]

        def normalize_company_tokens(name: str):
            """
            Returns (distinctive_tokens, acronyms)

            - Remove legal suffixes
            - Extract alpha tokens
            - Single short token (2..5 chars) => treat as acronym (ups/sap/bmw/ford)
            - Single token length>=3 => keep as distinctive token (ford)
            - Multi-word names: keep tokens len>=3, drop generic org tokens
            - If nothing distinctive remains: fall back to len>=5 tokens
            """
            legal_suffixes = [
                r"\bAG\b", r"\bGmbH\b", r"\bSE\b", r"\bCo KG\b", r"\bInc\b",
                r"\bLLC\b", r"\bS\.A\.\b", r"\bLtd\b", r"\bPte Ltd\b", r"\bS\.r\.l\b", r"\bBV\b"
            ]

            cleaned = (name or "").strip()
            for suffix in legal_suffixes:
                cleaned = re.sub(suffix, "", cleaned, flags=re.IGNORECASE).strip()
            cleaned = re.sub(r"\s{2,}", " ", cleaned)

            raw_parts = [p for p in re.split(r"[\s\-_,.]+", cleaned) if p]
            words = [p.lower() for p in raw_parts if p.isalpha()]

            # Single-token company handling (UPS, SAP, BMW, FORD)
            if len(words) == 1:
                w = words[0]
                if 2 <= len(w) <= 5:
                    return [], [w]
                if len(w) >= 3:
                    # treat as distinctive token (ford, spar, sony)
                    if w in self.GENERIC_ORG_TOKENS:
                        return [], []
                    return [w], []

            # Multi-word: keep len>=3
            candidates = [w for w in words if len(w) >= 3]
            # Remove generic org tokens for ownership matching
            distinctive = [w for w in candidates if w not in self.GENERIC_ORG_TOKENS]

            # If everything got filtered out, fall back to longest meaningful tokens (len>=5)
            if not distinctive:
                distinctive = [w for w in words if len(w) >= 5 and w not in self.GENERIC_ORG_TOKENS]

            distinctive = list(dict.fromkeys(distinctive))
            return distinctive, []

        def hostname_matches_company(hostname: str, name: str):
            """
            Conservative "family domain" matcher:
            - match against hostname labels (split on '.' and '-')
            - prefer distinctive tokens; require >=2 hits if possible
            - acronyms only count if exact label match
            """
            hn = (hostname or "").lower()
            if hn.startswith("www."):
                hn = hn[4:]
            labels = [lbl for lbl in re.split(r"[.\-]", hn) if lbl]

            tokens, acronyms = normalize_company_tokens(name)

            token_hits = 0
            for t in tokens:
                if any(lbl == t for lbl in labels):
                    token_hits += 1
                elif any(lbl.startswith(t) or lbl.endswith(t) for lbl in labels):
                    token_hits += 1

            acronym_hits = sum(1 for a in acronyms if any(lbl == a for lbl in labels))

            if len(tokens) >= 2 and token_hits >= 2:
                return True
            if len(tokens) == 1 and token_hits == 1:
                return True
            if acronym_hits >= 1 and len(tokens) == 0:
                return True
            return False

        def company_token_hits_in_path(path: str, name: str):
            """
            Returns count of matched distinctive tokens in the URL path/slug.
            Also supports concatenation match (red + bull => redbull).
            """
            tokens, acronyms = normalize_company_tokens(name)
            p = (path or "").lower()

            parts = [x for x in re.split(r"[^a-z0-9]+", p) if x]

            hits = 0
            for t in tokens:
                if t in parts:
                    hits += 1

            # Concatenation support: red + bull => redbull
            concat = "".join(tokens)
            if concat and any(concat in part for part in parts):
                hits = max(hits, 2 if len(tokens) >= 2 else 1)

            # Acronyms for single-token orgs (UPS/SAP/BMW/FORD)
            if acronyms:
                joined = "".join(parts)
                if any(a in parts for a in acronyms) or any(a in joined for a in acronyms):
                    hits = max(hits, 1)

            return hits, tokens, acronyms

        def is_relevant(url):
            url_lc = url.lower()
            parsed = urlparse(url_lc)
            hostname = (parsed.hostname or "").lower()
            if hostname.startswith("www."):
                hostname = hostname[4:]
            path = parsed.path or ""

            # quick reject (log which word caused it)
            for bad in DISALLOWED_KEYWORDS:
                if bad in url_lc:
                    if "hackerone.com" in hostname:
                        self.logger.debug(f"DROP(H1 disallowed='{bad}'): {url}")
                    return False

            has_keyword = any(kw in url_lc for kw in VDP_KEYWORDS)

            base_match = self._host_matches_base(hostname, base_host)
            external_match = self._host_is_whitelisted(hostname)
            company_host_match = hostname_matches_company(hostname, company_name)

            # Internal/family: require VDP keyword signal (precision)
            if (base_match or company_host_match) and has_keyword:
                if "hackerone.com" in hostname:
                    self.logger.debug(f"KEEP(H1 internal?? keyword): {url}")
                return True

            # Whitelisted external:
            if external_match:
                ok_path = self._external_platform_path_ok(hostname, path)
                hit_count, tokens, acronyms = company_token_hits_in_path(path, company_name)
                required_hits = 2 if len(tokens) >= 2 else 1

                if "hackerone.com" in hostname:
                    self.logger.debug(
                        f"H1 CHECK url={url} ok_path={ok_path} "
                        f"hit_count={hit_count} required={required_hits} "
                        f"tokens={tokens} acronyms={acronyms}"
                    )

                if ok_path and hit_count >= required_hits:
                    return True

                if "hackerone.com" in hostname:
                    self.logger.debug(f"DROP(H1) reason: ok_path={ok_path}, hits={hit_count}/{required_hits}")

            # If NOT base and NOT whitelisted, require VDP keyword in URL
            if not base_match and not external_match and not has_keyword:
                return False

            return False

        # Filter + canonicalize + dedupe
        # IMPORTANT FIX: re-check canonicalized external URL for platform path sanity
        seen = set()
        out = []
        for u in urls:
            if not is_relevant(u):
                continue

            canon = self.canonicalize_external_url(u)

            # prevent canonicalization from producing non-program roots like /engagements
            parsed_c = urlparse(canon)
            host_c = (parsed_c.hostname or "").lower()
            if host_c.startswith("www."):
                host_c = host_c[4:]
            path_c = parsed_c.path or ""

            if self._host_is_whitelisted(host_c) and not self._external_platform_path_ok(host_c, path_c):
                self.logger.debug(f"Dropping canonicalized external URL (path not ok): {canon}")
                continue

            if canon in seen:
                continue
            seen.add(canon)
            out.append(canon)

        return out

    @staticmethod
    def clean_url(url):
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
