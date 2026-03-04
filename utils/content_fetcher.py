import requests
import pdfplumber
from bs4 import BeautifulSoup
import io
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import time
from readability import Document

class ContentFetcher:
    def __init__(self, logger, pdf_size_limit_mb=1):
        self.logger = logger
        self.pdf_size_limit_mb = pdf_size_limit_mb


    def fetch_content(self, url):
        """
        Fetch the content of the given URL. Returns a dict with 'raw' and 'text' for HTML, or just plain text for PDFs.
        """
        try:
            self.logger.info(f"Fetching content from {url}")
            response = requests.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')

            if 'application/pdf' in content_type:
                content_length = len(response.content)
                pdf_text = self._handle_pdf(response, url, content_length)
                if pdf_text:
                    return {"raw": None, "text": pdf_text}
                return None
            else:
                raw_html, clean_text = self._fetch_html_with_playwright(url)
                if raw_html and clean_text:
                    return {"raw": raw_html, "text": clean_text}
                return None

        except requests.RequestException as e:
            self.logger.error(f"Error fetching content from {url}: {e}")
            return None

    def _handle_pdf(self, response, url, content_length):
        """
        Handle PDF content by extracting text.
        """
        try:
            if content_length:
                file_size = int(content_length)
                file_size_mb = file_size / (1024 * 1024)
                if file_size_mb > self.pdf_size_limit_mb:
                    self.logger.warning(f"PDF at {url} exceeds size limit ({self.pdf_size_limit_mb} MB).")
                    return None

            self.logger.info(f"Extracting text from PDF at {url}")
            return self._extract_text_from_pdf(response.content)
        except Exception as e:
            self.logger.error(f"Error processing PDF at {url}: {e}")
            return None

    def _fetch_html_with_playwright(self, url):
        """
        Use Playwright to fetch fully rendered HTML content.
        Tries hard to wait until JS-heavy pages are actually stable.
        """
        try:
            self.logger.info(f"Using Playwright to render HTML content from {url}")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    locale="en-US",
                )
                page = context.new_page()

                # 1️⃣ Navigate
                page.goto(url, timeout=20000)

                # 2️⃣ Wait until network is mostly quiet
                # This is MUCH better than "load"
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except PlaywrightTimeoutError:
                    self.logger.debug("networkidle timeout – continuing anyway")

                # 3️⃣ Optional: wait for DOM to stabilize (no size changes)
                self._wait_for_dom_stability(page, timeout=5000)

                # 4️⃣ Small safety delay (last async JS, CMP banners, etc.)
                page.wait_for_timeout(1000)

                raw_html = page.content()

                page.close()
                context.close()
                browser.close()

            clean_text = self.extract_clean_text_from_html(raw_html)

            return raw_html, clean_text

        except Exception as e:
            self.logger.warning(f"Playwright failed for {url}: {e}. Falling back to requests.")
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                raw_html = response.text
                soup = BeautifulSoup(raw_html, "html.parser")
                text = soup.get_text(separator="\n").strip()
                clean_text = " ".join(text.split())
                return raw_html, clean_text
            except Exception as fallback_error:
                self.logger.error(f"Fallback fetch also failed for {url}: {fallback_error}")
                return None, None
    

    def _wait_for_dom_stability(self, page, timeout=5000, poll_interval=500):
        """
        Wait until the DOM size stops changing.
        This catches late JS rendering, SPAs, consent banners, etc.
        """
        end_time = time.time() + (timeout / 1000)
        last_size = None

        while time.time() < end_time:
            size = page.evaluate("document.body.innerHTML.length")
            if size == last_size:
                return
            last_size = size
            page.wait_for_timeout(poll_interval)


    @staticmethod
    def _extract_text_from_pdf(pdf_content):
        """
        Extract text from a PDF using pdfplumber.
        """
        try:
            with pdfplumber.open(io.BytesIO(pdf_content)) as pdf:
                text = ""
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
            return text.strip()
        except Exception as e:
            raise RuntimeError(f"Error extracting text from PDF: {e}")
            return None
        
    @staticmethod    
    def extract_clean_text_from_html(raw_html: str) -> str:
        IMPORTANT_SELECTORS = [
            "main",
            "article",
            "[role=main]",
            "#content",
            ".content",
            ".main",
            ".main-content",
            ".page-content",
            ".container",
        ]

        IMPORTANT_KEYWORDS = [
            "vulnerability",
            "bug bounty",
            "responsible disclosure",
            "coordinated disclosure",
            "scope",
            "out of scope",
            "report",
            "security contact",
            "psirt",
        ]

        soup_full = BeautifulSoup(raw_html, "html.parser")

        # -------- 1) Readability (high precision) --------
        readable_text = ""
        try:
            doc = Document(raw_html)
            readable_html = doc.summary(html_partial=True)
            soup_readable = BeautifulSoup(readable_html, "html.parser")
            readable_text = soup_readable.get_text(separator="\n").strip()
        except Exception:
            readable_text = ""

        # -------- 2) Semantic DOM extraction (high recall) --------
        semantic_chunks = []

        for sel in IMPORTANT_SELECTORS:
            for el in soup_full.select(sel):
                text = el.get_text(separator="\n").strip()
                if len(text) > 200:
                    semantic_chunks.append(text)

        semantic_text = "\n".join(semantic_chunks)

        # -------- 3) Fallback: keyword-driven blocks --------
        keyword_chunks = []
        full_text = soup_full.get_text(separator="\n").lower()

        if any(k in full_text for k in IMPORTANT_KEYWORDS):
            keyword_chunks.append(soup_full.get_text(separator="\n"))

        # -------- 4) Merge intelligently --------
        combined = "\n".join([
            readable_text,
            semantic_text,
            "\n".join(keyword_chunks)
        ])

        # -------- 5) Cleanup --------
        clean = " ".join(combined.split())

        return clean