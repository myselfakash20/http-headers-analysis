# HTTP Headers Analysis - Cybersecurity

## Overview
The HTTP Headers Analysis tool helps identify and analyze HTTP headers in web traffic. It provides insight into security vulnerabilities related to the misconfiguration or improper handling of HTTP headers, which can lead to potential risks like:

**Cross-Site Scripting (XSS)** </br>
**Clickjacking**</br>
**Sensitive Information Disclosure**</br>

This tool can detect issues such as missing security headers, misconfigured CORS policies, and server information leakage. The tool offers both:</br>

Command-Line Interface (CLI) via http_headers_analysis.py</br>
Web-Based Dashboard via dashboard.py</br>

**🔥 How It Helps in Cybersecurity**</br>

HTTP headers play a critical role in the security of web applications. By analyzing them, security analysts can spot misconfigurations and vulnerabilities. Some key benefits of this tool are:</br>

Detect Missing Headers: Identify missing headers like Content Security Policy (CSP), X-Content-Type-Options, and X-XSS-Protection, which are crucial for security.</br>
Spot Misconfigured CORS Headers: Detect overly permissive CORS headers that could allow unauthorized data sharing.</br>
Expose Security Issues: Reveal server information, framework details, and other sensitive information that could be exploited by attackers.</br>

**💰 How It Helps in Bug Bounty**</br>
This tool can help bug bounty hunters find vulnerabilities related to misconfigured HTTP headers, a common issue in bounty programs. Key benefits:</br>

Find Vulnerabilities Faster: Automate header scanning and reduce manual work.</br>
Focus on Important Headers: Identify weak headers and prioritize what to report.</br>
Professional Reports: Generate CSV/JSON reports for submission to bounty platforms.</br>


***📦 Installation***

1️⃣ Clone the Repository
Clone the repository to your local machine using Git:

```
git clone https://github.com/myselfakash20/http-headers-analysis.git
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

Terminal Mode: Use the CLI tool (http_headers_analysis.py) for quick scans.</br>
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
If you'd like a more interactive, user-friendly interface, use the Streamlit dashboard.</br>

Run the Dashboard</br>
Run the following command:

```
python3 -m streamlit run dashboard.py
```
This will launch a web-based dashboard.

**How to Use the Dashboard**


Enter a URL or Upload a File (CSV or TXT) with URLs.</br>
Customize Header Risk Weights: Set the priority (risk weight) for each header.</br>
Click "Scan URLs": The tool will scan and display the following.</br>
Interactive Table: Shows the missing/present headers for each URL.</br>
Bar Chart: Shows the risk score for each URL.</br>
Pie Chart: Compares the ratio of Present vs Missing headers.</br>
Export Results:</br>
After the scan, you can export results as CSV or JSON.</br>

Email Alerts (Optional)</br>
If any URLs have a HIGH risk, you can send an email alert.</br>

Note: You need to set up the email configuration in dashboard.py.


**📘 Example Usage**

*1️⃣ Terminal Mode*

```
python3 http_headers_analysis.py -u https://example.com
```
Output:
```
URL: https://example.com
Strict-Transport-Security: Missing
Content-Security-Policy: Present
X-Frame-Options: Missing
Total Risk Score: 7
Risk Level: 🔴 HIGH
```

*2️⃣ Web Dashboard*
Run the dashboard:
```
python3 -m streamlit run dashboard.py
```

View the interactive dashboard in your browser at http://localhost:8501.</br>
Upload a file of URLs (CSV/TXT) or type a URL directly.


**🧑‍💻 Technologies Used**

Python	  :Core programming language
Streamlit	:For the web-based dashboard
Requests	:To make HTTP requests
Plotly	  :For bar and pie chart visualizations
Pandas	  :For data manipulation (CSV/JSON)
Colorama	:For color-coded terminal output

**📈 Key Features**

Batch Scanning: Scan a list of URLs at once.</br>
Export Results: Export scan results to CSV or JSON.</br>
Interactive Dashboard: See risk analysis and charts for each URL.</br>
Risk Weight Customization: Set priority for each header.</br>
Email Alerts: Get alerts for HIGH risk URLs.</br>

**🚀 Future Enhancements**
Advanced Email Alerts: Email daily reports of risky URLs.</br>
Scheduled Scans: Automatically run scans at regular intervals.</br>
Advanced Visualizations: Add charts for individual header presence.</br>

**🤝 Contributing**
Want to contribute? Fork the repo and submit a pull request.</br>
Here’s how to get started:</br>

Fork the repo.</br>
Create a new branch (feature/your-feature-name).</br>
Make your changes and commit them.</br>
Submit a pull request for review.</br>

**📜 License**
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as you see fit.
