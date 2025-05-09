# 🛡️ AI-VPD-Scanner

**AI-VPD-Scanner** is an intelligent Python crawler that identifies and analyzes **vulnerability disclosure policies (VDPs)** and **bug bounty programs** from company websites using `security.txt`, Google search, and GPT-4o.

---

## 🚀 Features

- Automatically identifies `security.txt` and VDP pages from company websites
- Uses **Google Custom Search** as a fallback to locate disclosure policy URLs
- Fetches and analyzes content using **OpenAI’s GPT-4o**
- Extracts structured fields:
  - Contact email/form
  - Safe harbor clause
  - Bounty/swag offers
  - Disclosure timeline
  - Public disclosure terms
  - PGP key availability
  - Hall of Fame and more
- GPT-based **confidence scoring** to select the most relevant page
- Outputs clean, structured JSON

---

## 📁 Input Format

Provide a CSV with the following format:

```
Company Name,Base URL
Example Inc,https://example.com
Acme Corp,https://acme.io
```

---

## 🧠 How GPT-Based Analysis Works

### 🔍 `analyze_content(...)` – Structured Extraction

Once a policy page is identified, its content is passed to GPT-4o. The model is instructed to extract:

- `policy_url`, `contact_email`, `contact_url`
- `safe_harbor`, `offers_bounty`, `offers_swag`
- `disclosure_timeline_days`, `pgp_key`, `hall_of_fame`
- `public_disclosure`, `preferred_languages`, `hiring`
- Many other optional fields

GPT responds in a **validated JSON schema format**, which is then cleaned (e.g., `"self"` values are replaced with the source URL).

---

### 📈 `analyze_probability(...)` – Confidence Scoring

To determine which of many possible URLs is worth analyzing, the tool uses GPT to assign a **confidence score (0 to 1)** indicating how likely a page is to contain a valid vulnerability disclosure or bug bounty policy.

- Pages with confidence **above 0.6** are considered
- The one with the **highest score** is selected

---

## 🧰 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/c-leitner/AI-VDP-Scanner.git
cd ai-vpd-scanner
```

### 2. Set Up a Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Required Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Playwright Browsers (for dynamic content)

This project uses Playwright to render JavaScript-heavy pages like HackerOne.

After installing the Python package, install the browser binaries:

```bash
playwright install
```
This command must be run once after setup.

---

## 🔐 .env Configuration

Create a `.env` file in the project root directory with the following keys:

```env
OPENAI_API_KEY=your_openai_api_key
GOOGLE_API_KEY=your_google_api_key
CSE_ID=your_custom_search_engine_id
```


---

## ▶️ Usage

Run the scanner with your input CSV and desired output JSON file:

```bash
python ai-vpd-scanner.py --input path/to/input.csv --output path/to/output.json
```

---

## 📦 Project Structure

```
ai-vpd-scanner/
├── ai-vpd-scanner.py
├── requirements.txt
├── .env
├── utils/
│   ├── chatgpt_analyzer.py
│   ├── content_fetcher.py
│   ├── google_search_handler.py
│   ├── logger.py
│   └── security_txt_handler.py
├── Logs/
│   └── ai-vpd-scanner.log
├── Data/
│   ├── Input/
│   │   └── test-companies.csv
│   └── Output/
│       └── results.json
```

---

## 📄 Output Example

The output is a structured JSON file that includes:

```json
{
  "company_name": "Example Inc",
  "base_url": "https://example.com",
  "security_txt_url": "https://example.com/.well-known/security.txt",
  "policy_url": "https://example.com/vdp",
  "highest_confidence": 0.85,
  "analysis": {
    "contact_email": "security@example.com",
    "safe_harbor": "full",
    "offers_bounty": "yes"
  }
}
```

---

## 📘 License

MIT License. See [LICENSE](LICENSE) for more details.

---

## 🙌 Acknowledgments

This project relies on the following open-source libraries and APIs:

- [OpenAI API](https://platform.openai.com/) – GPT-4o for policy analysis and confidence scoring  
- [Playwright for Python](https://playwright.dev/python/) – Headless browser automation for JavaScript-rendered pages (e.g., HackerOne)  
- [Requests](https://docs.python-requests.org/) – Robust HTTP client for fetching web and PDF content  
- [pdfplumber](https://github.com/jsvine/pdfplumber) – PDF parsing and text extraction  
- [BeautifulSoup (bs4)](https://www.crummy.com/software/BeautifulSoup/) – HTML parsing and content cleanup  
- [google-search-results-python](https://github.com/abenassi/google-search-results-python) – Google Programmable Search API wrapper  
- [sectxt](https://pypi.org/project/sectxt/) – Standard-compliant parser for `security.txt` files  
- [python-dotenv](https://github.com/theskumar/python-dotenv) – Loads environment variables from `.env` files  