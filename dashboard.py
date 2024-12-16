import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Default Headers and Risk Weights (modifiable via sliders)
SECURITY_HEADERS = {
    'Strict-Transport-Security': {'description': 'Prevents MITM attacks, enforces HTTPS', 'risk': 'HIGH', 'weight': 3},
    'Content-Security-Policy': {'description': 'Mitigates XSS attacks by controlling resource loading', 'risk': 'HIGH', 'weight': 3},
    'X-Frame-Options': {'description': 'Prevents Clickjacking attacks', 'risk': 'MEDIUM', 'weight': 2},
    'X-Content-Type-Options': {'description': 'Prevents MIME sniffing', 'risk': 'MEDIUM', 'weight': 2},
    'Permissions-Policy': {'description': 'Controls access to browser features', 'risk': 'LOW', 'weight': 1},
    'Referrer-Policy': {'description': 'Controls referrer information sent with requests', 'risk': 'LOW', 'weight': 1},
    'X-XSS-Protection': {'description': 'Provides XSS protection (legacy)', 'risk': 'LOW', 'weight': 1}
}

# --------------- Functions ---------------
def analyze_headers(url, custom_weights):
    """Analyze the security headers for a given URL."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        result = {'URL': url}
        total_risk_score = 0
        missing_headers = []

        for header, details in SECURITY_HEADERS.items():
            if header in headers:
                result[header] = '✅ Present'
            else:
                result[header] = '❌ Missing'
                total_risk_score += custom_weights.get(header, details['weight'])
                missing_headers.append(header)

        if total_risk_score <= 3:
            risk_level = '🟢 LOW'
        elif 4 <= total_risk_score <= 7:
            risk_level = '🟡 MEDIUM'
        else:
            risk_level = '🔴 HIGH'

        result['Total Risk Score'] = total_risk_score
        result['Risk Level'] = risk_level
        result['Missing Headers'] = ', '.join(missing_headers) if missing_headers else 'None'
        
        return result
    except requests.exceptions.RequestException as e:
        st.error(f"Error analyzing {url}: {e}")
        return {'URL': url, 'Status': 'Failed'}

def send_email_alert(results, recipient_email):
    """Send an email alert if any URLs have a HIGH Risk Score."""
    high_risk_urls = [result['URL'] for result in results if '🔴 HIGH' in result.get('Risk Level', '')]
    if not high_risk_urls:
        st.success("No HIGH risk URLs detected, so no email was sent.")
        return

    subject = "🚨 HTTP Headers Analysis - HIGH RISK ALERT 🚨"
    body = f"""
    The following URLs have been flagged as HIGH risk:
    {', '.join(high_risk_urls)}

    Please review and secure these URLs.
    """
    sender_email = "akashghoshcomputer@gmail.com"  # Replace with your email
    password = "Akash@2002Pappu"  # Replace with your email password

    try:
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()
        st.success(f"🚀 Email alert sent to {recipient_email}!")
    except Exception as e:
        st.error(f"Error sending email: {e}")

# --------------- Streamlit Dashboard ---------------
st.set_page_config(page_title="HTTP Headers Risk Dashboard", layout="wide")

# Sidebar
st.sidebar.title("📊 HTTP Headers Analysis Dashboard")
uploaded_file = st.sidebar.file_uploader("Upload a .txt or .csv file with URLs", type=['txt', 'csv'])
url = st.sidebar.text_input("Or, enter a single URL (e.g., https://example.com)")

st.sidebar.markdown("### Customize Header Risk Weights")
custom_weights = {}
for header, details in SECURITY_HEADERS.items():
    custom_weights[header] = st.sidebar.slider(f'{header} (Default: {details["weight"]})', 1, 5, details['weight'])

scan_button = st.sidebar.button("🔍 Scan URLs")

# Results Section
st.title("🛠️ HTTP Headers Risk Dashboard")

if scan_button:
    urls = []

    if uploaded_file:
        file_type = uploaded_file.name.split('.')[-1]
        if file_type == 'txt':
            urls = uploaded_file.read().decode('utf-8').splitlines()
        elif file_type == 'csv':
            df = pd.read_csv(uploaded_file)
            if 'URL' in df.columns:
                urls = df['URL'].tolist()

    if url:
        urls.append(url)

    if urls:
        results = []
        for i, url in enumerate(urls):
            st.info(f"🔍 Scanning ({i+1}/{len(urls)}) headers for {url}...")
            result = analyze_headers(url, custom_weights)
            results.append(result)

        df = pd.DataFrame(results)
        
        st.markdown("## 📋 **Headers Report**")
        st.dataframe(df)

        # Export Buttons
        st.markdown("## 📤 **Export Results**")
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(label="📥 Download as CSV", data=csv, file_name='headers_report.csv', mime='text/csv')

        json_data = df.to_json(orient='records')
        st.download_button(label="📥 Download as JSON", data=json_data, file_name='headers_report.json', mime='application/json')

        # Bar Chart
        chart_data = df[['URL', 'Total Risk Score']]
        fig = px.bar(chart_data, x='URL', y='Total Risk Score', title='Risk Scores for Each URL')
        st.plotly_chart(fig)

        # Pie Chart
        total_present = sum(['✅' in str(val) for val in df.iloc[:, 2:].values.flatten()])
        total_missing = sum(['❌' in str(val) for val in df.iloc[:, 2:].values.flatten()])
        pie_data = pd.DataFrame({'Header Status': ['Present', 'Missing'], 'Count': [total_present, total_missing]})
        fig2 = px.pie(pie_data, values='Count', names='Header Status', title='Header Presence')
        st.plotly_chart(fig2)

        # Email Alert
        recipient_email = st.text_input("Enter email to send alerts for HIGH risk URLs")
        if st.button("🚨 Send Email Alert"):
            send_email_alert(results, recipient_email)
    else:
        st.warning("⚠️ No URLs to scan. Please upload a file or enter a URL.")
else:
    st.info("👈 Upload a file or enter a URL in the sidebar to start scanning.")
