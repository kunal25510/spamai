"""
Sentinel Security Agent - Trusted Domains & URL Analysis
Provides robust domain parsing, SLD alignment, deceptive subdomain detection,
and visible link mismatch verification without naive single-domain assumptions.
"""

import re
import urllib.parse

# Curated reference organizations and their primary root domains
# Used to verify brand alignment and protect against impersonation.
# Companies routinely use multiple TLDs/domains (.com, .news, .in, .app, .org, mailer domains).
TRUSTED_ORGANIZATIONS = {
    # Educational & Career Platforms
    "unstop.com": "Unstop",
    "unstop.news": "Unstop",
    "internshala.com": "Internshala",
    "coursera.org": "Coursera",
    "edx.org": "edX",
    "udemy.com": "Udemy",
    "codecademy.com": "Codecademy",
    "kaggle.com": "Kaggle",
    "hackerrank.com": "HackerRank",
    "leetcode.com": "LeetCode",
    "geeksforgeeks.org": "GeeksforGeeks",
    "naukri.com": "Naukri",
    "foundit.in": "Foundit",

    # Major Tech & Cloud Infrastructure
    "google.com": "Google",
    "googlemail.com": "Google",
    "googleapis.com": "Google",
    "accounts.google.com": "Google",
    "notifications.google.com": "Google",
    "github.com": "GitHub",
    "githubstatus.com": "GitHub",
    "gitlab.com": "GitLab",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "linkedin.com": "LinkedIn",
    "spotify.com": "Spotify",
    "canva.com": "Canva",
    "adobe.com": "Adobe",
    "slack.com": "Slack",
    "notion.so": "Notion",
    "atlassian.com": "Atlassian",
    "zoom.us": "Zoom",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon",
    "flipkart.com": "Flipkart",
    "railway.app": "Railway",
    "render.com": "Render",
    "facebook.com": "Facebook",
    "facebookmail.com": "Facebook",

    # Government & Verified Utilities
    "india.gov.in": "National Portal of India",
    "nic.in": "National Informatics Centre",
    "ippb.in": "India Post Payments Bank",
    "ippbonline.com": "India Post Payments Bank",
    "ippbonline.co.in": "India Post Payments Bank",
    "indiapost.gov.in": "India Post",
    "zerossl.com": "ZeroSSL",
    "letsencrypt.org": "Let's Encrypt"
}

# Trusted Institutional TLD suffixes (.edu, .ac.in, etc.)
TRUSTED_TLD_SUFFIXES = (
    ".edu",
    ".ac.in",
    ".edu.in",
    ".gov.in",
    ".res.in",
    ".gov",
    ".mil"
)

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
}

# Disposable high-risk TLDs commonly used in throwaway attack campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "click", "buzz", "fit", "work", "rest", "tk", "ml", "ga", "cf", "gq", "icu"
}

# Major brand targets and their authentic domain families
# A brand is aligned if the sender domain's SLD base matches the brand name
BRAND_DOMAIN_FAMILIES = {
    "google": ["google.com", "googlemail.com", "googleapis.com", "google.co.in"],
    "unstop": ["unstop.com", "unstop.news", "unstop.in", "unstop.org"],
    "internshala": ["internshala.com"],
    "linkedin": ["linkedin.com", "linkedin.cn"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "github": ["github.com", "githubstatus.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonsellerservices.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "facebookmail.com"],
    "railway": ["railway.app"],
    "render": ["render.com"],
    "ippb": ["ippb.in", "ippbonline.com", "ippbonline.co.in", "indiapost.gov.in"],
    "sbi": ["sbi.co.in", "statebankofindia.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com"]
}

# Technical terms ending with .js or similar extensions that are NOT domain names
NON_URL_TECH_TOKENS = {
    "node.js", "next.js", "react.js", "vue.js", "angular.js", "express.js",
    "d3.js", "chart.js", "three.js", "threejs", "moment.js", "anime.js",
    "lodash.js", "socket.io", "electron.js"
}


def extract_email_address(raw_from):
    """Extracts display name and clean email address from a 'From' header string."""
    if not raw_from:
        return "", ""
    match = re.search(r'^(.*?)\s*<([^>]+)>', raw_from)
    if match:
        display_name = match.group(1).strip().strip('"').strip("'")
        email_addr = match.group(2).strip().lower()
        return display_name, email_addr
    clean = raw_from.strip().strip('"').strip("'").lower()
    return "", clean


def extract_domain(email_address):
    """Extracts domain portion of an email address."""
    if "@" in email_address:
        return email_address.split("@")[-1].strip().lower().replace(">", "")
    return ""


def get_root_domain(domain):
    """
    Extracts registrable root domain (e.g. delivery.unstop.news -> unstop.news).
    Handles multi-part ccTLDs (.co.in, .gov.in, .ac.in, .edu.in, .co.uk).
    """
    if not domain:
        return ""
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()

    two_part_tlds = {"co.in", "gov.in", "ac.in", "edu.in", "org.in", "net.in", "co.uk", "org.uk", "ac.uk"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def get_sld_base(domain):
    """
    Extracts the core second-level brand label of a domain.
    Examples:
      - unstop.news -> 'unstop'
      - unstop.com -> 'unstop'
      - engage.canva.com -> 'canva'
      - priority.facebookmail.com -> 'facebookmail'
      - ippbonline.co.in -> 'ippbonline'
    """
    root = get_root_domain(domain)
    if not root:
        return ""
    parts = root.split(".")
    return parts[0].lower()


def is_trusted_domain(domain):
    """Checks whether the domain matches a verified authentic organization or institutional TLD."""
    if not domain:
        return False, None
    domain = domain.lower()
    root_domain = get_root_domain(domain)

    if domain in TRUSTED_ORGANIZATIONS:
        return True, TRUSTED_ORGANIZATIONS[domain]
    if root_domain in TRUSTED_ORGANIZATIONS:
        return True, TRUSTED_ORGANIZATIONS[root_domain]

    # Check institutional TLDs (.edu, .ac.in, .gov.in, etc.)
    for suffix in TRUSTED_TLD_SUFFIXES:
        if domain.endswith(suffix):
            return True, f"Verified Institution ({suffix})"

    return False, None


def check_brand_impersonation(display_name, sender_domain, has_threat_context=False):
    """
    Evaluates display name against actual sender domain across ALL brands and domains.
    Distinguishes:
      1. Domain Aligned: Display name and sender domain share common brand/identity
         (e.g. 'Unstop' on 'unstop.news', 'Render' on 'render.com', 'Canva' on 'engage.canva.com').
      2. True Brand Impersonation: Display name claims a high-profile brand while sender domain is
         disparate AND corroborating threat evidence exists (or disposable/free webmail).
      3. Domain Ownership Unverified: Display name differs from sender domain, but ownership
         cannot be verified. Reports 'domain ownership unverified' instead of asserting impersonation.
    
    Returns:
      (is_impersonation_bool, details_dict_or_None)
    """
    if not display_name or not sender_domain:
        return False, None

    disp_clean = display_name.strip().strip('"').strip("'")
    disp_lower = disp_clean.lower()
    sender_root = get_root_domain(sender_domain)
    sender_sld = get_sld_base(sender_domain)

    # Extract alphanumeric words from display name, excluding common noise tokens
    tokens = [t for t in re.findall(r'[a-z0-9]+', disp_lower) if len(t) >= 3]
    noise_tokens = {
        "team", "support", "from", "the", "official", "customer", "care", "service",
        "helpdesk", "notifications", "alerts", "info", "news", "newsletter", "via",
        "group", "community", "security", "account", "updates", "mailer", "billing"
    }
    significant_tokens = [t for t in tokens if t not in noise_tokens]

    # 1. Check for Domain Alignment across ANY brand
    is_aligned = False
    for token in significant_tokens:
        if token == sender_sld:
            is_aligned = True
            break

    # Also check known brand domain families
    for brand_key, family_domains in BRAND_DOMAIN_FAMILIES.items():
        if re.search(r'\b' + re.escape(brand_key) + r'\b', disp_lower):
            if sender_root in family_domains or sender_domain in family_domains:
                is_aligned = True
                break
            if sender_sld == brand_key:
                is_aligned = True
                break

    if is_aligned:
        return False, {
            "status": "ALIGNED",
            "impersonated_brand": None,
            "claimed_brand": disp_clean,
            "actual_domain": sender_domain,
            "description": f"Sender domain '{sender_domain}' aligns with claimed identity '{disp_clean}'."
        }

    # 2. Check for High-Profile Brand Impersonation vs Unverified Domain
    for brand_key, family_domains in BRAND_DOMAIN_FAMILIES.items():
        if re.search(r'\b' + re.escape(brand_key) + r'\b', disp_lower):
            is_free_webmail = sender_root in {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"}
            is_high_risk = sender_root.split(".")[-1] in HIGH_RISK_TLDS

            # Only assert definitive brand impersonation if accompanied by threat context or throwaway infrastructure
            if has_threat_context or is_free_webmail or is_high_risk:
                return True, {
                    "status": "IMPERSONATION",
                    "impersonated_brand": brand_key.title(),
                    "claimed_brand": brand_key,
                    "actual_domain": sender_domain,
                    "description": f"Display name claims to be '{brand_key.title()}' but actual sender domain is '{sender_domain}'."
                }
            else:
                return False, {
                    "status": "UNVERIFIED",
                    "impersonated_brand": None,
                    "claimed_brand": brand_key.title(),
                    "actual_domain": sender_domain,
                    "description": f"Domain ownership unverified: display name claims '{brand_key.title()}' on domain '{sender_domain}'."
                }

    # 3. For any other entity / company display name where domain cannot be verified
    if len(significant_tokens) >= 1 and not is_aligned:
        return False, {
            "status": "UNVERIFIED",
            "impersonated_brand": None,
            "claimed_brand": disp_clean,
            "actual_domain": sender_domain,
            "description": f"Domain ownership unverified: display name '{disp_clean}' on domain '{sender_domain}'."
        }

    return False, None


def parse_url_details(url):
    """
    Parses a URL and inspects structural features without fetching or executing.
    Correctly identifies genuine deceptive subdomains (brand in prefix of unrelated root)
    without flagging authentic multi-domain properties (delivery.unstop.news, storage.googleapis.com).
    """
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        if not netloc:
            parsed = urllib.parse.urlparse("http://" + url)
            netloc = parsed.netloc.lower()

        # Strip port
        host = netloc.split(":")[0]
        if not host:
            return {
                "url": url, "host": "", "root_domain": "", "is_ip": False,
                "is_shortener": False, "is_high_risk_tld": False,
                "is_deceptive": False, "deceptive_target": None
            }

        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
        root_domain = get_root_domain(host) if not is_ip else host
        is_shortener = host in URL_SHORTENERS or root_domain in URL_SHORTENERS

        tld = host.split(".")[-1] if "." in host else ""
        is_high_risk_tld = tld in HIGH_RISK_TLDS

        # Deceptive Subdomain Analysis:
        # A domain is deceptive ONLY when a target brand appears in a SUBDOMAIN PREFIX
        # on an UNRELATED third-party root domain (e.g., 'google.com.phish-vps.ru' or 'unstop.com.attacker.site').
        # It is NOT deceptive if the brand IS the root domain itself (e.g., 'delivery.unstop.news', 'storage.googleapis.com').
        is_deceptive = False
        deceptive_target = None

        if not is_ip and "." in host:
            host_parts = host.split(".")
            root_parts = root_domain.split(".")

            # Subdomain prefix consists of all parts before the root domain
            if len(host_parts) > len(root_parts):
                subdomain_prefix = ".".join(host_parts[:-len(root_parts)])
                root_sld = get_sld_base(root_domain)

                for brand_key, family_domains in BRAND_DOMAIN_FAMILIES.items():
                    # If brand appears in subdomain prefix
                    if brand_key in subdomain_prefix:
                        # If the root domain itself is owned by or affiliated with the brand, it is authentic!
                        if root_domain in family_domains or brand_key in root_sld:
                            continue

                        # If root domain is an authentic trusted service, not deceptive
                        if is_trusted_domain(root_domain)[0]:
                            continue

                        # Brand in subdomain on unrelated root domain -> DECEPTIVE!
                        is_deceptive = True
                        deceptive_target = brand_key
                        break

        return {
            "url": url,
            "host": host,
            "root_domain": root_domain,
            "is_ip": is_ip,
            "is_shortener": is_shortener,
            "is_high_risk_tld": is_high_risk_tld,
            "is_deceptive": is_deceptive,
            "deceptive_target": deceptive_target
        }
    except Exception:
        return {
            "url": url,
            "host": "",
            "root_domain": "",
            "is_ip": False,
            "is_shortener": False,
            "is_high_risk_tld": False,
            "is_deceptive": False,
            "deceptive_target": None
        }


def check_mismatched_url(anchor_text, href):
    """
    Checks if visible anchor text displays one web destination while href points to a different domain.
    Does NOT treat programming terms (e.g. 'Node.js', 'Next.js', 'React.js') as URLs.
    Does NOT flag subdomains sharing the same root domain (e.g. 'status.railway.app' vs 'railway.app').
    """
    if not anchor_text or not href:
        return False, None

    anchor_clean = anchor_text.strip().lower()

    # Ignore common tech terms that end with .js or .io
    if anchor_clean in NON_URL_TECH_TOKENS:
        return False, None

    # Check if anchor is formatted as an intended URL
    # Must start with http://, https://, www., or contain domain + path (e.g. domain.com/path)
    is_url_like = (
        anchor_clean.startswith("http://") or
        anchor_clean.startswith("https://") or
        anchor_clean.startswith("www.") or
        bool(re.search(r'^[a-z0-9\-]+\.[a-z]{2,}(?:/[^\s]*)?$', anchor_clean))
    )

    if not is_url_like:
        return False, None

    # Do not treat phrases containing whitespace as URLs
    if " " in anchor_clean:
        return False, None

    displayed_parsed = parse_url_details(anchor_clean)
    actual_parsed = parse_url_details(href)

    if displayed_parsed["root_domain"] and actual_parsed["root_domain"]:
        # If both share the same root domain (e.g. status.railway.app and railway.app), not mismatched!
        if displayed_parsed["root_domain"] != actual_parsed["root_domain"]:
            return True, {
                "displayed_domain": displayed_parsed["root_domain"],
                "actual_domain": actual_parsed["root_domain"]
            }

    return False, None
