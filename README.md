Secret Guardian

Code Secret Guardian API: a modular security API, built with Python and FastAPI, that scans code for hardcoded passwords, API keys and database credentials before they are saved or pushed.

Why this exists

Accidentally committing secrets such as passwords or keys to a repository is a common and costly security mistake. Secret Guardian checks code against a set of detection rules and reports any findings, so problems can be caught early.

Features
Scan raw code sent as text, or an uploaded code file
Detection rules are stored in a configuration file (config/rules.json), so rules can be changed without editing the code
Returns a clear result: whether the code is secure, how many findings there were, and the details of each finding
Input validation and error handling (for example, non-UTF-8 files are rejected with a clear 400 error)
Health-check endpoint that reports how many rules are loaded
Interactive API documentation generated automatically by FastAPI
[EDIT: list the types of secrets your rules detect, e.g. passwords, API keys, database connection strings, tokens]
Tech Stack
Python
FastAPI and Pydantic
Uvicorn (server) [EDIT: confirm it is in your requirements file]
Project Structure
secret-guardian/
|-- app.py              # FastAPI application and endpoints
|-- engine/             # Scanning logic (SecretScanner)
|-- config/             # Detection rules (rules.json)
|-- requirements.txt    # Python dependencies
Getting Started

Prerequisites: Python 3.9+ [EDIT: confirm your version]

bash
git clone https://github.com/NdumisoZulu053/secret-guardian.git
cd secret-guardian
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
uvicorn app:app --reload

The API runs at http://127.0.0.1:8000. Open http://127.0.0.1:8000/docs for the interactive documentation.

API Endpoints
Method	Endpoint	Description
POST	/api/v1/scan/text	Scan code sent as a JSON string
POST	/api/v1/scan/file	Scan an uploaded UTF-8 text file
GET	/health	Check the API is running and see the number of loaded rules
Example: scan text

Request

json
POST /api/v1/scan/text
{
  "filename": "config.py",
  "code": "DB_PASSWORD = 'my-secret-password'"
}

Response

json
{
  "is_secure": false,
  "total_findings": 1,
  "findings": [ ... ]
}

[EDIT: replace the findings with the real output from running your API]

Example: scan a file
bash
curl -X POST "http://127.0.0.1:8000/api/v1/scan/file" -F "file=@example.py"
Error handling
Files that are not UTF-8 plain text return 400 Bad Request with a clear message.
If the rules file is missing, the API starts with no rules instead of crashing, and /health shows loaded_rules: 0.
How It Works
On startup the API loads the detection rules from config/rules.json.
A request sends code (as text or a file) to the SecretScanner in the engine module.
The scanner checks the content against each rule and returns any findings.
The API responds with is_secure, total_findings and the list of findings.
Possible Improvements
Add unit tests with pytest
Mask detected secrets in the output
Add more rules (cloud keys, tokens, private keys)
Add a Dockerfile and a GitHub Actions workflow for automatic testing
Add a pre-commit hook that calls the API
Author

Ndumiso Blessing Zulu | IT student (UNISA) | github.com/NdumisoZulu053
