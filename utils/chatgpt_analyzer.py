from openai import OpenAI
import json
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

class ChatGPTAnalyzer:
    def __init__(self, api_key, logger):
        self.client = OpenAI(api_key=api_key)
        self.logger = logger

    def analyze_content(self, content, company_name, url):
        """
        Use GPT to analyze content for vulnerability disclosure policy details.
        Returns a structured JSON-like dictionary with extracted details.
        """
        try:
            self.logger.info(f"Analyzing content for {company_name} using ChatGPT.")

            # Your custom prompt
            prompt = (
                f"Analyze the following content for the presence of a vulnerability disclosure policy for {company_name}. "
                "If present, determine if it includes the following details:\n"
                "- policy_url: Self if policy is present, otherwise empty\n"
                "- contact_email: Contact email for disclosure\n"
                "- contact_url: If a form is provided, URL of the form\n"
                "- safe_harbor: Safe harbor clause (if no legal action = full) (full, partial, empty)\n"
                "- offers_swag: Swag (goodies) offered (boolean)\n"
                "- disclosure_timeline_days: Disclosure timeline (number in days, 0 if not specifically stated)\n"
                "- public_disclosure: If public disclosure is offered (nda, discretionary, coordinated)\n"
                "- pgp_keys_provided: URL to PGP key or 'self' if the key is in the content\n"
                "- offers_bounty: Bounties offered (yes, no, partial)\n"
                "- hall_of_fame: Hall of fame URL, empty, or 'self' if on the same site\n"
                "- preferred_language: In the following format (en, de, fr, etc.)\n"
                "Return the results as a JSON object."
            )

            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a cybersecurity policy analyzer."},
                    {"role": "user", "content": prompt + f"\n\n{content}"}
                ],
        response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "discloseio_program-list-schema",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "program_name": {
                                "type": "string"
                                },
                                "policy_url": {
                                "type": "string",
                                "format": "uri"
                                },
                                "policy_url_status": {
                                "type": "string",
                                "enum": [
                                    "alive",
                                    "dead"
                                ]
                                },
                                "contact_url": {
                                "type": "string",
                                "format": "uri"
                                },
                                "contact_email": {
                                "type": "string",
                                "format": "email"
                                },
                                "launch_date": {
                                "anyOf": [
                                    {
                                    "type": "string",
                                    "enum": [
                                        ""
                                    ]
                                    },
                                    {
                                    "type": "string",
                                    "format": "date"
                                    }
                                ]
                                },
                                "offers_bounty": {
                                "type": "string",
                                "enum": [
                                    "yes",
                                    "no",
                                    "partial"
                                ]
                                },
                                "offers_swag": {
                                "type": "boolean"
                                },
                                "hall_of_fame": {
                                "type": "string",
                                "format": "uri"
                                },
                                "safe_harbor": {
                                "type": "string",
                                "enum": [
                                    "full",
                                    "partial",
                                    "none"
                                ]
                                },
                                "public_disclosure": {
                                "type": "string",
                                "enum": [
                                    "nda",
                                    "discretionary",
                                    "co-ordinated",
                                    ""
                                ]
                                },
                                "disclosure_timeline_days": {
                                "type": "number",
                                "minimum": 0
                                },
                                "pgp_key": {
                                "type": "string",
                                "format": "uri"
                                },
                                "hiring": {
                                "type": "string",
                                "format": "uri"
                                },
                                "securitytxt_url": {
                                "type": "string",
                                "format": "uri"
                                },
                                "preferred_languages": {
                                "type": "string"
                                }
                            }
                        }
                    }
                },
                model="gpt-4o",
            )

            # Parse and return the structured JSON response
            result = json.loads(response.choices[0].message.content)
            return self.cleanup(result,url)
        except Exception as e:
            self.logger.error(f"Error analyzing content for {company_name} at {url}: {e}")
            return {
                "program_name": "{company_name}",
                "policy_url": "{url}",
            }
        
    def cleanup(self, data, policy_url):
        """
        Clean up the analyzed JSON response:
        - Replace "self" with the policy URL.
        - Remove empty fields.
        - Remove disclosure_timeline_days if it is 0.
        - Always remove the policy_url_status field.
        """
        try:
            self.logger.info("Cleaning up the response.")

            def recursive_cleanup(d):
                if isinstance(d, dict):
                    return {
                        key: recursive_cleanup(value)
                        for key, value in d.items()
                        if value not in ("", None)  # Remove empty values
                        and not (key == "disclosure_timeline_days" and value == 0)  # Remove days = 0
                        and key != "policy_url_status"  # Always remove this field
                    }
                elif isinstance(d, list):
                    return [recursive_cleanup(item) for item in d if item not in ("", None)]
                elif isinstance(d, str) and d.strip().lower() == "self":
                    return policy_url  # Replace "self" with policy URL
                else:
                    return d

            cleaned_data = recursive_cleanup(data)
            self.logger.info("Response cleaned successfully.")
            return cleaned_data
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            return data

    def analyze_probability(self, content, company_name, url):
        """
        Use GPT to assess the probability that the content contains a vulnerability disclosure policy.
        Returns a confidence score between 0 and 1.
        """
        raw_html = content.get("raw", "")
        clean_text = content.get("text", "")
        try:
            # --- Special handling for hackerone.com (based on already rendered content) ---
            if "hackerone.com" in url.lower():
                self.logger.info(f"Analyzing HackerOne page content at {url}")
                soup = BeautifulSoup(raw_html, 'html.parser')
                # Check for external program indicators
                meta_tag = soup.find("meta", {"name": "description", "class": "spec-external-unclaimed"})
                external_span = soup.find("span", class_="font-bold", string=lambda s: s and "external program" in s.lower())

                if meta_tag or external_span:
                    self.logger.info(f"HackerOne URL {url} identified as 'External Program'. Confidence: 0.0")
                    return 0.0
                else:
                    self.logger.info(f"HackerOne URL {url} identified as an internal program. Confidence: 1.0")
                    return 1.0

            # --- Standard GPT-4o analysis ---
            prompt = (
                f"Analyze this content for {company_name}:\n\n"
                f"{clean_text[:5000]}\n\n"
                "Return a confidence score (float 0-1) indicating how likely it includes a vulnerability disclosure policy/bug bounty program."
            )

            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a cybersecurity policy analyzer."},
                    {"role": "user", "content": prompt}
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "discloseio_program-list-schema",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "confidence": {"type": "number"}
                            }
                        }
                    }
                },
                model="gpt-4o",
            )

            response_content = response.choices[0].message.content
            parsed_response = json.loads(response_content)
            confidence = parsed_response.get("confidence", 0)
            return max(0.0, min(1.0, float(confidence)))

        except Exception as e:
            self.logger.error(f"Error assessing probability for {company_name}: {e}")
            return 0.0