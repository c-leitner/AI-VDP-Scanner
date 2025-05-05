import requests
import pdfplumber
from bs4 import BeautifulSoup
import io
from playwright.sync_api import sync_playwright

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
        Use Playwright to fetch HTML content and return both raw HTML and cleaned plain text.
        """
        try:
            self.logger.info(f"Using Playwright to render HTML content from {url}")
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)
                context = browser.new_context()
                page = context.new_page()
                page.goto(url, timeout=10000)
                page.wait_for_load_state("load")

                raw_html = page.content()

                # Ensure everything closes properly
                page.close()
                context.close()
                browser.close()


            soup = BeautifulSoup(raw_html, 'html.parser')
            text = soup.get_text(separator="\n").strip()
            clean_text = " ".join(text.split())

            return raw_html, clean_text

        except Exception as e:
            self.logger.warning(f"Playwright failed for {url}: {e}. Falling back to requests.")
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                raw_html = response.text
                soup = BeautifulSoup(raw_html, 'html.parser')
                text = soup.get_text(separator="\n").strip()
                clean_text = " ".join(text.split())
                return raw_html, clean_text
            except Exception as fallback_error:
                self.logger.error(f"Fallback fetch also failed for {url}: {fallback_error}")
                return None, None

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