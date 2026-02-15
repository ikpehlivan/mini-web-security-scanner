\# Mini Web Security Scanner



A lightweight Python-based CLI tool designed to perform basic web security checks such as:



\- Security header analysis

\- Heuristic reflected XSS detection

\- Heuristic error-based SQL Injection detection

\- Sensitive file and endpoint exposure checks



This project was built as a practical demonstration of fundamental web application security testing techniques.



---



\## ⚠️ Disclaimer



This tool is intended for \*\*authorized security testing and educational purposes only\*\*.



The findings produced are heuristic-based and must always be manually validated by a security professional.



The author assumes no responsibility for misuse.



---



\## 🎯 Project Goals



The main objectives of this project are:



\- Demonstrate core web application security testing logic

\- Build a clean, structured CLI security tool

\- Produce structured JSON-based reports

\- Showcase practical offensive security skills in a minimal codebase

\- Provide a foundation for future improvements



---



\## 🧠 What This Scanner Does



\### 1️⃣ Security Header Analysis



Checks for missing or weak HTTP security headers:



\- Content-Security-Policy

\- X-Content-Type-Options

\- X-Frame-Options

\- Referrer-Policy

\- Permissions-Policy

\- Strict-Transport-Security (HTTPS only)



Missing headers are reported as misconfiguration findings.



---



\### 2️⃣ Reflected XSS (Heuristic Detection)



If query parameters exist:



\- Injects XSS payloads into parameters

\- Compares baseline vs injected response

\- Flags potential reflections



⚠️ This does NOT confirm exploitability.

Manual validation is required.



---



\### 3️⃣ Basic SQL Injection (Error-Based Detection)



\- Appends SQL payloads to query parameters

\- Detects common database error patterns:

&nbsp; - MySQL

&nbsp; - PostgreSQL

&nbsp; - MSSQL

&nbsp; - Oracle

&nbsp; - SQLite



Only error-based patterns are checked.



---



\### 4️⃣ Sensitive Path Exposure



Attempts to access common sensitive endpoints:



\- /.env

\- /.git/config

\- /admin

\- /phpinfo.php

\- /server-status

\- /robots.txt

\- /.well-known/security.txt



Accessible sensitive resources are reported.



---



\## 🏗️ Project Structure



mini-web-security-scanner/

│

├── scanner.py

├── requirements.txt

├── README.md

│

└── payloads/

├── xss.txt

└── sqli.txt





---



\## ⚙️ Installation



\### 1️⃣ Clone the repository



```bash

git clone https://github.com/ikpehlivan/mini-web-securit-scanner.git

cd mini-web-security-scanner



2️⃣ Install dependencies

pip install -r requirements.txt



Python 3.10+ is recommended.



🚀 Usage

Scan a Single URL

python scanner.py -u "https://example.com/search?q=test" -o report.json



Scan Multiple Targets

python scanner.py -l targets.txt -o report.json



Where targets.txt contains:

https://example.com/?q=test

https://testphp.vulnweb.com/listproducts.php?cat=1



📄 Output Format



The scanner generates a structured JSON report:



\[

&nbsp; {

&nbsp;   "target": "https://example.com/?q=test",

&nbsp;   "timestamp": 1700000000,

&nbsp;   "findings": \[

&nbsp;     {

&nbsp;       "type": "xss",

&nbsp;       "severity": "medium",

&nbsp;       "title": "Possible reflected XSS",

&nbsp;       "evidence": "Parameter 'q' reflected payload.",

&nbsp;       "url": "https://example.com/?q=<payload>"

&nbsp;     }

&nbsp;   ]

&nbsp; }

]





Each finding includes:

Type

Severity

Title

Evidence

Affected URL

Additional metadata (if applicable)



🛠️ Detection Methodology

The scanner uses:

HTTP response comparison (baseline vs injected)

Regex-based database error detection

Direct endpoint probing

Header presence validation

It intentionally avoids:

Aggressive fuzzing

Brute force attacks

Time-based blind injection

Automated exploitation

This keeps the scanner lightweight and safe for demonstration purposes.



🔒 Ethical Use

Only scan:

Applications you own

Applications you have explicit written authorization to test

Bug bounty programs that allow automated testing

Never test production systems without permission.

