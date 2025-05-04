import json
from logger import Logger
from security_txt_handler import SecurityTxtHandler
from google_search_handler import GoogleSearchHandler
from content_fetcher import ContentFetcher
from chatgpt_analyzer import ChatGPTAnalyzer
from dotenv import load_dotenv
import os
        

def test_security_txt_handler():
    # Initialize logger
    logger = Logger("security_txt_test.log")

    # Initialize the SecurityTxtHandler
    handler = SecurityTxtHandler(logger)

    # Define test cases
    test_cases = [
        {"url": "https://securitytxt.org", "description": "Valid security.txt URL"},
        {"url": "https://www.diepresse.com", "description": "No security.txt file"},
        {"url": "https://golem1.de", "description": "Inaccessible site"}
    ]

    for test in test_cases:
        url = test["url"]
        description = test["description"]
        logger.info(f"Testing {description} ({url})")
        
        # Test the method
        try:
            security_txt_url, policy_url, source = handler.check_security_txt(url)
            logger.info(f"Result for {url} - security_txt_url: {security_txt_url}, policy_url: {policy_url}, source: {source}")
        except Exception as e:
            logger.error(f"Error testing {url}: {e}")

def test_google_search_handler():
    load_dotenv()
    logger = Logger("google_search_test.log")
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")  # Replace with your Google API key or place in .env file
    CSE_ID = os.getenv("CSE_ID")       # Replace with your Google CSE ID or place in .env file

    handler = GoogleSearchHandler(GOOGLE_API_KEY, CSE_ID, logger)

    test_cases = [
        {"company_name": "enbw.com", "base_url": "https://enbw.com", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Valid site with results"},
        {"company_name": "Bayer AG", "base_url": "https://www.bayer.com", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Valid site with results"},
        {"company_name": "ZF Friedrichshafen AG", "base_url": "https://zf.com", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Valid site with results"},
        {"company_name": "Siemens", "base_url": "https://siemens.com", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Valid site with results"},
        {"company_name": "Liebherr-International Deutschland Gmbh", "base_url": "https://www.liebherr.com", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Valid site with results"},
        {"company_name": "Raiffeisen Bankengruppe Österreich", "base_url": "https://www.raiffeisen.at/", "keywords": ["vulnerability disclosure policy", "bug bounty program", "vulnerability response", "vdp", "Reporting a vulnerability", "PSIRT"], "description": "Non-existent site"},
    ]

    for test in test_cases:
        logger.info(f"Testing {test['description']} ({test['company_name']})")
        try:
            urls, source = handler.search(test["base_url"], test["keywords"])
            if urls:
                logger.info(f"Results for {test['company_name']}: {urls}")
            else:
                logger.info(f"No results found for {test['company_name']}")
        except Exception as e:
            logger.error(f"Error testing {test['company_name']}: {e}")


def test_content_fetcher():
    logger = Logger("content_fetcher_test.log")
    fetcher = ContentFetcher(logger)

    test_cases = [
        {"url": "https://www.enbw.com/media/enbw-cert/cvd-richtlinie_v1-1_de-en.pdf", "description": "Valid PDF file"},
        {"url": "https://www.infineon.com/dgdl/Vulnerability_Notification_Process.pdf?fileId=8ac78c8b7ca35f7b017ca6d98b1c0000", "description": "Valid PDF file"},
        {"url": "https://www.siemens.com/global/en/products/services/cert/vulnerability-process.html", "description": "Valid HTML page"},
        {"url": "https://www.iana.org/_img/2015.1/iana-logo-homepage.svg", "description": "Unsupported content type"},
    ]

    for test in test_cases:
        logger.info(f"Testing {test['description']} ({test['url']})")
        try:
            content = fetcher.fetch_content(test["url"])
            if content:
                logger.info(f"Content fetched from {test['url']}:\n{content[:500]}...")  # Show first 500 chars
            else:
                logger.info(f"No content fetched from {test['url']}")
        except Exception as e:
            logger.error(f"Error testing {test['url']}: {e}")

def test_chatgpt_analyzer():
    logger = Logger("chatgpt_analyzer_test.log")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Replace with your OpenAI API key or place in .env file
    analyzer = ChatGPTAnalyzer(OPENAI_API_KEY, logger)

    # Test content examples
    test_cases = [
        {
            "company_name": "EnBW",
            "url": "https://www.enbw.com/media/enbw-cert/cvd-richtlinie_v1-1_de-en.pdf",
            "content": "Die EnBW legt großen Wert auf die Sicherheit ihrer IT-Systeme. Trotz sorgfältigster Implementierung, Konfiguration und Prüfung können dennoch Schwachstellen vorhanden sein. Der Entdecker einer Schwachstelle schafft keine neue Schwachstelle. Wenn ein Entdecker die Existenz einer Schwachstelle jedoch nicht bekannt gibt, ist das keine Garantie dafür, dass ein anderer sie nicht finden wird - oder sie nicht bereits gefunden hat. Entdecker von Schwachstellen können ihre Gründe haben, die Schwach- stelle öffentlich zu machen; dabei ist eine koordinierte Offenlegung immer zu bevorzugen. Für Meldung verwenden sie folgende email: security@enwb.com.",
            "description": "Valid policy content",
        },
        {
            "company_name": "NoPolicyCorp",
            "url": "https://example.com/no-policy",
            "content": "This is a general page with no mention of a vulnerability disclosure policy.",
            "description": "No policy content",
        },
    ]

    for test in test_cases:
        logger.info(f"Testing {test['description']} ({test['company_name']})")
        try:
            # Analyze content
            details = analyzer.analyze_content(test["content"], test["company_name"], test["url"])
            logger.info(f"Analysis details: {json.dumps(details, indent=4)}")

            # Assess probability
            probability = analyzer.analyze_probability(test["content"], test["company_name"])
            logger.info(f"Policy presence probability: {probability}")
        except Exception as e:
            logger.error(f"Error during test for {test['company_name']}: {e}")


# Run the test function
if __name__ == "__main__":
    test_security_txt_handler()
    test_google_search_handler()
    test_content_fetcher()
    test_chatgpt_analyzer()
