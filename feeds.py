from urllib.parse import urlsplit

import requests


def fetch_malicious_domains():
    try:
        # Request a list of known malicious domains from urlhaus.abuse.ch
        response = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=10)
        domains = set()
        for line in response.text.splitlines():
            # Skip lines not containing URLs
            if line.startswith("#") or not line.strip():
                continue
            # Extract only the hostname from the URL
            domain_name = urlsplit(line).hostname
            domains.add(domain_name)
        return domains
    except requests.RequestException as e:
        # Return an empty set if the request fails
        print(f"[!] Failed to fetch malicious domain feed: {e}")
        return set()
