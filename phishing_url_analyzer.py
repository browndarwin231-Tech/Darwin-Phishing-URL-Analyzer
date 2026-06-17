suspicious_keywords = ["login", "verify", "secure", "update", "account", "bank", "gift", "prize"]

print("=== Darwin Phishing URL Analyzer ===\n")

with open("suspicious_urls.txt", "r") as file:
    urls = file.readlines()

for url in urls:
    url = url.strip()
    risk_score = 0

    print(f"\nChecking URL: {url}")

    if url.startswith("http://"):
        print("[WARNING] Uses insecure HTTP")
        risk_score += 1

    if any(keyword in url.lower() for keyword in suspicious_keywords):
        print("[WARNING] Contains suspicious keyword")
        risk_score += 1

    if any(char.isdigit() for char in url.split("//")[-1].split("/")[0]):
        print("[WARNING] Contains numbers in domain or IP address")
        risk_score += 1

    if risk_score >= 2:
        print("[HIGH RISK] Possible phishing URL")
    elif risk_score == 1:
        print("[MEDIUM RISK] Review recommended")
    else:
        print("[LOW RISK] No obvious phishing indicators") 