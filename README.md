# HTTP Headers Analysis - Cybersecurity

## Overview
The HTTP Headers Analysis tool helps identify and analyze HTTP headers in web traffic. It provides insight into security vulnerabilities related to the misconfiguration or improper handling of HTTP headers, which can lead to potential risks like:

Cross-Site Scripting (XSS)
Clickjacking
Sensitive Information Disclosure
This tool can detect issues such as missing security headers, misconfigured CORS policies, and server information leakage. The tool offers both:

Command-Line Interface (CLI) via http_headers_analysis.py
Web-Based Dashboard via dashboard.py
🔥 How It Helps in Cybersecurity
HTTP headers play a critical role in the security of web applications. By analyzing them, security analysts can spot misconfigurations and vulnerabilities. Some key benefits of this tool are:

Detect Missing Headers: Identify missing headers like Content Security Policy (CSP), X-Content-Type-Options, and X-XSS-Protection, which are crucial for security.
Spot Misconfigured CORS Headers: Detect overly permissive CORS headers that could allow unauthorized data sharing.
Expose Security Issues: Reveal server information, framework details, and other sensitive information that could be exploited by attackers.
💰 How It Helps in Bug Bounty
This tool can help bug bounty hunters find vulnerabilities related to misconfigured HTTP headers, a common issue in bounty programs. Key benefits:

Find Vulnerabilities Faster: Automate header scanning and reduce manual work.
Focus on Important Headers: Identify weak headers and prioritize what to report.
Professional Reports: Generate CSV/JSON reports for submission to bounty platforms.


***📦 Installation***

1️⃣ Clone the Repository
Clone the repository to your local machine using Git:

```
git clone https://github.com/yourusername/http-headers-analysis.git
cd http-headers-analysis
```
2️⃣ Install Dependencies
Install the required libraries by running:

```
pip install -r requirements.txt
```
Note: Make sure you have Python 3.7+ installed. If you encounter issues, try creating a virtual environment:

```
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

**📋 How to Use It**

You can use the tool in two modes:

Terminal Mode: Use the CLI tool (http_headers_analysis.py) for quick scans.
Web-Based Mode: Use the Streamlit-based dashboard (dashboard.py) for a visual, interactive experience.

`🔥 Option 1: Terminal Mode (http_headers_analysis.py)`
If you prefer working in the terminal, you can use http_headers_analysis.py.

Scan a Single URL
Run the following command in your terminal:

```
python3 http_headers_analysis.py -u https://example.com
```
Scan Multiple URLs
If you have multiple URLs listed in a file (urls.txt), you can scan them all at once:
```
python3 http_headers_analysis.py -f urls.txt
```
Note: The file (e.g., urls.txt) should have one URL per line.

***Export Results:***
You can export the scan results to CSV or JSON:

```
python http_headers_analysis.py -f urls.txt -o csv  # Export to CSV
python http_headers_analysis.py -f urls.txt -o json  # Export to JSON
```
`🔥 Option 2: Web-Based Mode (dashboard.py)`
If you'd like a more interactive, user-friendly interface, use the Streamlit dashboard.

Run the Dashboard
Run the following command:

```
python3 -m streamlit run dashboard.py
```
This will launch a web-based dashboard.

**How to Use the Dashboard**

<ins>
Enter a URL or Upload a File (CSV or TXT) with URLs.
Customize Header Risk Weights: Set the priority (risk weight) for each header.
Click "Scan URLs": The tool will scan and display the following:
Interactive Table: Shows the missing/present headers for each URL.
Bar Chart: Shows the risk score for each URL.
Pie Chart: Compares the ratio of Present vs Missing headers.
Export Results
After the scan, you can export results as CSV or JSON.

Email Alerts (Optional)
If any URLs have a HIGH risk, you can send an email alert.

Note: You need to set up the email configuration in dashboard.py.
</ins>
📘 Example Usage

1️⃣ Terminal Mode

python http_headers_analysis.py -u https://example.com
Output:
```
URL: https://example.com
Strict-Transport-Security: Missing
Content-Security-Policy: Present
X-Frame-Options: Missing
Total Risk Score: 7
Risk Level: 🔴 HIGH
```

2️⃣ Web Dashboard
Run the dashboard:

python3 -m streamlit run dashboard.py

View the interactive dashboard in your browser at http://localhost:8501.
Upload a file of URLs (CSV/TXT) or type a URL directly.


**🧑‍💻 Technologies Used**

Python	  :Core programming language
Streamlit	:For the web-based dashboard
Requests	:To make HTTP requests
Plotly	  :For bar and pie chart visualizations
Pandas	  :For data manipulation (CSV/JSON)
Colorama	:For color-coded terminal output

📈 Key Features

Batch Scanning: Scan a list of URLs at once.
Export Results: Export scan results to CSV or JSON.
Interactive Dashboard: See risk analysis and charts for each URL.
Risk Weight Customization: Set priority for each header.
Email Alerts: Get alerts for HIGH risk URLs.

🚀 Future Enhancements
Advanced Email Alerts: Email daily reports of risky URLs.
Scheduled Scans: Automatically run scans at regular intervals.
Advanced Visualizations: Add charts for individual header presence.

🤝 Contributing
Want to contribute? Fork the repo and submit a pull request.
Here’s how to get started:

Fork the repo.
Create a new branch (feature/your-feature-name).
Make your changes and commit them.
Submit a pull request for review.

📜 License
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as you see fit.
