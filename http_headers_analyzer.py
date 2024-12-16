import requests
import pandas as pd
import argparse
import json
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize Colorama (for Windows compatibility)
init(autoreset=True)

# List of security headers to check and their risk weights
SECURITY_HEADERS = {
    'Strict-Transport-Security': {'description': 'Prevents MITM attacks, enforces HTTPS', 'risk': 'HIGH', 'weight': 3},
    'Content-Security-Policy': {'description': 'Mitigates XSS attacks by controlling resource loading', 'risk': 'HIGH', 'weight': 3},
    'X-Frame-Options': {'description': 'Prevents Clickjacking attacks', 'risk': 'MEDIUM', 'weight': 2},
    'X-Content-Type-Options': {'description': 'Prevents MIME sniffing', 'risk': 'MEDIUM', 'weight': 2},
    'Permissions-Policy': {'description': 'Controls access to browser features', 'risk': 'LOW', 'weight': 1},
    'Referrer-Policy': {'description': 'Controls referrer information sent with requests', 'risk': 'LOW', 'weight': 1},
    'X-XSS-Protection': {'description': 'Provides XSS protection (legacy)', 'risk': 'LOW', 'weight': 1}
}

def colorize_risk(risk):
    """Color-code the risk level."""
    if risk == 'HIGH':
        return f"{Fore.RED}{risk}{Style.RESET_ALL}"
    elif risk == 'MEDIUM':
        return f"{Fore.YELLOW}{risk}{Style.RESET_ALL}"
    elif risk == 'LOW':
        return f"{Fore.GREEN}{risk}{Style.RESET_ALL}"
    return risk

def analyze_headers(url):
    """Analyze HTTP headers of a given URL and calculate the risk score."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        report = {'URL': url, 'Status': 'Success'}
        total_risk_score = 0
        missing_headers = []

        for header, details in SECURITY_HEADERS.items():
            if header in headers:
                report[header] = 'Present'
            else:
                report[header] = 'Missing'
                total_risk_score += details['weight']
                missing_headers.append(header)

        # Classify overall risk level
        if total_risk_score <= 3:
            risk_level = 'LOW'
        elif 4 <= total_risk_score <= 7:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'

        report['Total_Risk_Score'] = total_risk_score
        report['Overall_Risk'] = colorize_risk(risk_level)
        report['Missing_Headers'] = ', '.join(missing_headers) if missing_headers else 'None'

        return report

    except requests.exceptions.RequestException as e:
        print(f"Error: Could not retrieve headers for {url} - {e}")
        return {'URL': url, 'Status': 'Failed', 'Total_Risk_Score': 'N/A', 'Overall_Risk': 'N/A', 'Missing_Headers': 'N/A'}

def export_to_csv(results, filename='headers_report.csv'):
    """Export results to CSV"""
    df = pd.DataFrame(results)
    df.to_csv(filename, index=False)
    print(f'[+] Report exported to {filename}')

def export_to_json(results, filename='headers_report.json'):
    """Export results to JSON"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f'[+] Report exported to {filename}')

def display_terminal_report(results):
    """Display a clean table of the results in the terminal"""
    table = []
    for result in results:
        table.append([
            result['URL'],
            result['Status'],
            result['Total_Risk_Score'],
            result['Overall_Risk'],
            result['Missing_Headers']
        ])
    
    headers = ['URL', 'Status', 'Total Risk Score', 'Risk Level', 'Missing Headers']
    print("\n" + tabulate(table, headers=headers, tablefmt='pretty'))  # Pretty table view

def main():
    parser = argparse.ArgumentParser(description="HTTP Headers Analysis Tool with Risk Scoring and Terminal Report")
    parser.add_argument('-u', '--url', type=str, help='Single URL to scan')
    parser.add_argument('-f', '--file', type=str, help='File with list of URLs (one URL per line)')
    parser.add_argument('-o', '--output', type=str, default='csv', choices=['csv', 'json'], help='Output format (csv or json)')
    args = parser.parse_args()

    urls = []

    if args.url:
        urls.append(args.url)

    if args.file:
        try:
            with open(args.file, 'r') as file:
                urls.extend(file.read().splitlines())
        except FileNotFoundError:
            print(f"Error: File {args.file} not found.")
            return

    results = []
    for url in urls:
        print(f"\n[+] Scanning {url}...")
        report = analyze_headers(url)
        results.append(report)

    display_terminal_report(results)  # Show the report in the terminal

    if args.output == 'csv':
        export_to_csv(results)
    else:
        export_to_json(results)

if __name__ == "__main__":
    main()
