import csv
import json
import argparse
from dotenv import load_dotenv
import os
from utils.security_txt_handler import SecurityTxtHandler
from utils.google_search_handler import GoogleSearchHandler
from utils.content_fetcher import ContentFetcher
from utils.chatgpt_analyzer import ChatGPTAnalyzer
from utils.logger import Logger


class AIVPDScanner:
    def __init__(self, openai_api_key, google_api_key, cse_id, logger):
        """
        Initialize the AI-VDP-Scanner with necessary components.
        """
        self.logger = logger
        self.security_txt_handler = SecurityTxtHandler(logger)
        self.google_search_handler = GoogleSearchHandler(google_api_key, cse_id, logger)
        self.content_fetcher = ContentFetcher(logger)
        self.chatgpt_analyzer = ChatGPTAnalyzer(openai_api_key, logger)

    def process_company(self, company_name, base_url):
        """
        Process a single company:
        - Check `security.txt`
        - Perform Google search as fallback
        - Fetch content from URLs
        - Analyze content with ChatGPT
        Returns structured JSON with analysis results.
        """
        try:
            self.logger.info(f"Processing company: {company_name} ({base_url})")
            analysis_result = {"company_name": company_name, "base_url": base_url}

            # Step 1: Check for security.txt
            security_txt_url, policy_url, source = self.security_txt_handler.check_security_txt(base_url)
            analysis_result["security_txt_url"] = security_txt_url or ""
            analysis_result["policy_url"] = policy_url or ""

            # Step 2: Fallback to Google search if no policy URL found
            if not policy_url or not security_txt_url:
                urls, source = self.google_search_handler.search(base_url, company_name, [
                    "vulnerability disclosure policy",
                    "bug bounty program",
                    "vulnerability response",
                    "vdp",
                    "Reporting a vulnerability",
                    "PSIRT"
                ])
                analysis_result["google_search_results"] = urls
                
                policy_url, highest_confidence = self._fetch_and_find_best_url(company_name, urls)
                analysis_result["policy_url"] = policy_url or ""
                analysis_result["highest_confidence"] = highest_confidence

            # Step 3: Fetch content from the policy URL
            content = self.content_fetcher.fetch_content(policy_url) if policy_url else None
            if not content:
                self.logger.warning(f"No content fetched for {policy_url}")
                analysis_result["analysis"] = {}
                return analysis_result

            # Step 4: Analyze content with ChatGPT
            gpt_analysis = self.chatgpt_analyzer.analyze_content(content, company_name, policy_url)
            analysis_result["analysis"] = gpt_analysis

            # Step 5: Assess probability of policy presence
            #probability = self.chatgpt_analyzer.analyze_probability(content, company_name,policy_url)
            #analysis_result["probability"] = probability

            self.logger.info(f"Completed processing for {company_name}.")
            return analysis_result
        except Exception as e:
            self.logger.error(f"Error processing company {company_name} ({base_url}): {e}")
            return {"company_name": company_name, "base_url": base_url, "error": str(e)}

    def _fetch_and_find_best_url(self, company_name, urls):
        """
        Fetch content from multiple URLs and calculate confidence for each.
        Return the URL with the highest confidence above the threshold of 0.6.
        """
        try:
            highest_confidence = 0.0
            best_url = None
            confidence_threshold = 0.6  # Minimum acceptable confidence score

            for url in urls:
                self.logger.info(f"Fetching and analyzing content from {url} for {company_name}")
                content = self.content_fetcher.fetch_content(url)
                if content:
                    confidence = self.chatgpt_analyzer.analyze_probability(content, company_name, url)
                    self.logger.info(f"Confidence for {url}: {confidence}")
                    
                    # Only consider URLs with confidence above the threshold
                    if confidence > confidence_threshold:
                        if confidence > highest_confidence:
                            highest_confidence = confidence
                            best_url = url
                    else:
                        self.logger.info(f"URL {url} rejected due to low confidence: {confidence}")

            if best_url:
                self.logger.info(f"Best URL selected: {best_url} with confidence {highest_confidence}")
            else:
                self.logger.warning(f"No suitable URL found for {company_name} with confidence above {confidence_threshold}.")

            return best_url, highest_confidence
        except Exception as e:
            self.logger.error(f"Error fetching and analyzing URLs for {company_name}: {e}")
            return None, 0.0

    def process_csv(self, input_csv, output_json):
        """
        Process a CSV file of companies, analyze each, and output results to JSON.
        """
        try:
            self.logger.info(f"Processing input CSV: {input_csv}")
            results = []

            with open(input_csv, mode="r", newline="", encoding="utf-8") as infile:
                reader = csv.reader(infile)
                header = next(reader)  # Skip header row

                for row in reader:
                    company_name, base_url = row[0], row[1].strip()
                    result = self.process_company(company_name, base_url)
                    results.append(result)

            # Write results to output JSON
            with open(output_json, mode="w", encoding="utf-8") as outfile:
                json.dump(results, outfile, indent=4)

            self.logger.info(f"Results written to {output_json}")
        except Exception as e:
            self.logger.error(f"Error processing CSV: {e}")


if __name__ == "__main__":
    load_dotenv()

    # Command-line argument parser
    parser = argparse.ArgumentParser(description="Run the AIVPDScanner on a CSV file.")
    parser.add_argument("--input", "-i", required=True, help="Path to the input CSV file")
    parser.add_argument("--output", "-o", required=True, help="Path to the output JSON file")
    args = parser.parse_args()

    # Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Replace with your OpenAI API key or place in .env file
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")  # Replace with your Google API key or place in .env file
    CSE_ID = os.getenv("CSE_ID")       # Replace with your Google CSE ID or place in .env file

    logger = Logger("Logs/ai-vpd-scanner.log")

    # Initialize and run the PolicyAnalyzer
    scanner = AIVPDScanner(OPENAI_API_KEY, GOOGLE_API_KEY, CSE_ID, logger)
    scanner.process_csv(args.input, args.output)