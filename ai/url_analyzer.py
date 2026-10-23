import re
from urllib.parse import urlparse, unquote

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy",
    "shorturl.at", "ow.ly", "goo.gl", "buff.ly", "adf.ly", "tiny.cc",
    "lnkd.in", "rebrand.ly"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "work", "cam", "rest", "loan",
    "kim", "gq", "cf", "tk", "ml", "cc", "monster", "icu", "site"
}

SENSITIVE_BRANDS = [
    "google", "microsoft", "paypal", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "github",
    "chase", "bankofamerica", "wellsfargo", "sbi", "hdfc", "icici",
    "binance", "coinbase", "metamask", "dropbox"
]

CREDENTIAL_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account-update",
    "security-update", "confirm", "auth", "wp-login.php", "banking", "wallet",
    "password-reset", "credential", "recover", "update-info"
]

IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def analyze_url(raw_url):
    """
    Safely analyzes a URL using local heuristics and urllib parsing.
    NEVER contacts the destination or follows redirects.
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "risk_level": "LOW",
            "risk_score": 0,
            "reasons": ["No URL provided."],
            "message": "Input was empty.",
            "analysis_type": "url",
            "details": {"url": ""}
        }

    url_clean = raw_url.strip()
    # Normalize scheme if user omitted it
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_clean):
        candidate_url = "http://" + url_clean
    else:
        candidate_url = url_clean

    try:
        parsed = urlparse(candidate_url)
    except Exception as e:
        return {
            "risk_level": "HIGH",
            "risk_score": 75,
            "reasons": [f"Malformed or unparseable URL structure: {str(e)}"],
            "message": "The provided URL is malformed and could not be safely parsed.",
            "analysis_type": "url",
            "details": {"raw_url": raw_url}
        }

    reasons = []
    score = 0
    hostname = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "").lower()
    scheme = parsed.scheme.lower()
    port = parsed.port

    # 1. Dangerous / Insecure Schemes
    if scheme in ["javascript", "data", "file", "vbscript"]:
        score += 80
        reasons.append(f"Dangerous URL scheme detected ({scheme}:) capable of client-side execution.")
    elif scheme == "http":
        score += 15
        reasons.append("Unencrypted connection (HTTP instead of HTTPS).")

    # 2. Embedded Credentials / Userinfo Trick (e.g. http://google.com@evil.com)
    if parsed.username or "@" in (parsed.netloc.split(":")[0]):
        score += 55
        reasons.append("Embedded credentials or '@' symbol in URL authority, often used to disguise actual destination.")

    # 3. IP Address Hostname (raw IP instead of domain name)
    if IPV4_PATTERN.match(hostname) or hostname.startswith("["):
        score += 50
        reasons.append(f"Direct IP address host ({hostname}) used instead of a registered domain name.")

    # 4. Punycode / Internationalized Domain Name (IDN homoglyph)
    if "xn--" in hostname:
        score += 35
        reasons.append("Punycode (xn--) encoding detected; commonly used in homoglyph lookalike attacks.")

    # 5. URL Shorteners
    if hostname in KNOWN_SHORTENERS:
        score += 25
        reasons.append(f"URL shortener detected ({hostname}), which obscures the real destination address.")

    # 6. Misleading Subdomains & Brand Lookalike / Typosquatting
    # E.g. paypal.com-security.net or google-verify.xyz
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    for brand in SENSITIVE_BRANDS:
        if brand in hostname:
            # If the brand appears, but is NOT the true second-level domain (e.g., brand is in subdomain or hyphenated)
            if not root_domain.startswith(brand + "."):
                score += 45
                reasons.append(f"Brand impersonation indicator: '{brand}' appears in the hostname but does not match the root domain ({root_domain}).")
                break

    # 7. Excessive subdomains (deep nesting, e.g. a.b.c.d.example.com)
    if len(parts) > 4 and not IPV4_PATTERN.match(hostname):
        score += 20
        reasons.append(f"Excessive subdomain nesting ({len(parts)} levels), frequently seen in evasive phishing URLs.")

    # 8. High-risk TLD check
    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"High-risk top-level domain (.{tld}) with elevated rates of disposable phishing abuse.")

    # 9. Credential Harvesting Paths
    matched_paths = [kw for kw in CREDENTIAL_PATH_KEYWORDS if kw in path]
    if matched_paths:
        score += 25
        reasons.append(f"Path contains credential harvesting keywords: {', '.join(matched_paths[:3])}.")

    # 10. Non-standard ports
    if port and port not in [80, 443]:
        score += 20
        reasons.append(f"Non-standard web port ({port}) specified.")

    # Score Clamping
    score = min(score, 100)

    # Determine risk level
    if score >= 50:
        risk_level = "HIGH"
        message = "High risk: Suspicious URL patterns strongly indicate potential phishing or evasion."
    elif score >= 25:
        risk_level = "MEDIUM"
        message = "Medium risk: URL contains cautionary indicators such as shortening, non-standard structure, or HTTP."
    else:
        risk_level = "LOW"
        message = "Low risk: No obvious phishing patterns or lookalike indicators detected in local heuristic inspection."
        if not reasons:
            reasons.append("Standard domain structure; no lookalike patterns, raw IPs, or credential paths identified.")

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "message": message,
        "analysis_type": "url",
        "details": {
            "hostname": hostname,
            "scheme": scheme,
            "path": path[:80],
            "disclaimer": "Local heuristic analysis only. No remote reputation servers were contacted; URLs passing these checks are not guaranteed safe."
        }
    }
