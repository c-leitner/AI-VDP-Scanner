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
        Fetch the HTML or text content of the given URL, including PDFs.
        """
        try:
            self.logger.info(f"Fetching content from {url}")
            response = requests.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')

            if 'application/pdf' in content_type:
                content_length = len(response.content)
                return self._handle_pdf(response, url, content_length)
            elif content_type.startswith('text/'):
                return self._handle_html(response.text, url)
            else:
                self.logger.warning(f"Unsupported content type at {url}: {content_type}")
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


    def _handle_html(self, html_content, url):
        """
        Handle HTML content by extracting plain text.
        Uses Playwright for dynamic JS-rendered content if needed.
        """
        try:
            self.logger.info(f"Parsing HTML content from {url}")

            if "hackerone.com" in url.lower():
                self.logger.info(f"Using Playwright for JS-rendered content at {url}")
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.goto(url, timeout=20000)
                    page.wait_for_load_state('networkidle')
                    content = page.content()
                    browser.close()
            else:
                # Fallback to static HTML
                decoded_content = html_content.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                content = decoded_content

            soup = BeautifulSoup(content, 'html.parser')
            text = soup.get_text(separator="\n").strip()
            return " ".join(text.split())

        except Exception as e:
            self.logger.error(f"Error processing HTML at {url}: {e}")
            return None

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