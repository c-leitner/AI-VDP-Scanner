import requests
import time
from urllib.parse import urlsplit, urlunsplit

class GoogleSearchHandler:
    def __init__(self, api_key, cse_id, logger):
        self.api_key = api_key
        self.cse_id = cse_id
        self.logger = logger

    def search(self, base_url, company_name, keywords, num_results=5, wait_time=1):
        """
        Perform a Google search using the Google Custom Search JSON API.
        Returns the first `num_results` search results as a list of URLs.
        """
        query = f"site:{base_url} {' OR '.join(keywords)}"
        search_url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": self.api_key,
            "cx": self.cse_id,
            "q": query,
            "num": num_results,
        }

        self.logger.info(f"Performing Google search for {company_name} with query: {query}")
        try:
            response = requests.get(search_url, params=params, timeout=10)
            response.raise_for_status()

            search_results = response.json()
            if "items" in search_results:
                urls = []
                for item in search_results["items"]:
                    cleaned_url = self.clean_url(item["link"])
                    urls.append(cleaned_url)
                    self.logger.info(f"Google search result found: {cleaned_url}")
                time.sleep(wait_time)  # Pause to avoid rate limits
                return urls, "google"
            else:
                self.logger.warning(f"No results found for {company_name}")
                return [], None
        except requests.RequestException as e:
            self.logger.error(f"Error during Google search for {company_name}: {e}")
            return [], None
        except KeyError:
            self.logger.warning(f"No 'items' in Google search response for {company_name}")
            return [], None

    @staticmethod
    def clean_url(url):
        """
        Remove query parameters and fragments from the URL.
        """
        parsed = urlsplit(url)
        cleaned_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
        return cleaned_url