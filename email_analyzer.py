import sys
import re
from email import message_from_file
import dns.resolver

def check_spf(domain):
    if not domain:
        return False
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith('"v=spf1') or txt.startswith('v=spf1'):
                return True
    except Exception:
        return False
    return False

def extract_urls(text):
    if not text:
        return []
    url_pattern = r'https?://[^\s"\'>]+'
    return re.findall(url_pattern, text)

def check_urls(urls):
    warnings = []
    for url in urls:
        if len(url) > 100:
            warnings.append(f"Suspiciously long URL: {url[:60]}...")
        if any(short in url.lower() for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
            warnings.append(f"Shortened URL detected: {url}")
        if '%' in url or '=' in url:
            warnings.append(f"Possibly encoded URL: {url}")
    return warnings

def get_domain_from_email(email_address):
    if not email_address:
        return None
    if '<' in email_address and '>' in email_address:
        email_address = email_address[email_address.find('<')+1:email_address.find('>')]
    parts = email_address.split('@')
    if len(parts) == 2:
        return parts[1].strip()
    return None

def parse_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        msg = message_from_file(f)

    headers = {
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Subject': msg.get('Subject'),
        'Return-Path': msg.get('Return-Path'),
    }

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                try:
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            body = ""

    return headers, body

def generate_report(headers, spf_valid, urls, url_warnings):
    lines = []
    lines.append("=== Email Security Analyzer Report ===\n")

    lines.append("Headers:")
    for key, value in headers.items():
        lines.append(f"  {key}: {value}")

    lines.append(f"\nSPF Record Check: {'PASS' if spf_valid else 'FAIL or Not Found'}")

    lines.append(f"\nURLs Found ({len(urls)}):")
    for url in urls:
        lines.append(f"  - {url}")

    if url_warnings:
        lines.append("\nURL Warnings:")
        for warn in url_warnings:
            lines.append(f"  * {warn}")
    else:
        lines.append("\nNo suspicious URLs detected.")

    lines.append("\n=====================================")
    return "\n".join(lines)

def main():
    if len(sys.argv) != 2:
        print("Usage: python email_analyzer.py <email_file.eml>")
        sys.exit(1)

    email_file = sys.argv[1]
    headers, body = parse_email(email_file)
    domain = get_domain_from_email(headers.get('Return-Path')) or get_domain_from_email(headers.get('From'))
    spf_valid = check_spf(domain)
    urls = extract_urls(body)
    url_warnings = check_urls(urls)

    report = generate_report(headers, spf_valid, urls, url_warnings)
    print(report)

if __name__ == "__main__":
    main()
