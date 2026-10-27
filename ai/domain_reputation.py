"""
Sentinel AI Security Agent - Universal Domain Reputation & Analysis System
Handles any domain (known, unseen, small businesses, universities, tech, global services)
without relying on a hardcoded static whitelist.
Detects homoglyphs, IDN/punycode, lookalike typosquatting, and tracks observed history.
"""

import os
import json
import datetime
import unicodedata
import urllib.parse
from trusted_domains import (
    extract_email_address,
    extract_domain,
    get_root_domain
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
REPUTATION_FILE = os.path.join(DATA_DIR, "domain_reputation.json")

# High-profile reference domains used strictly for typosquatting / lookalike detection
REFERENCE_TARGET_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "linkedin.com", "paypal.com", "unstop.com", "internshala.com", "netflix.com",
    "dropbox.com", "spotify.com", "adobe.com", "zoom.us", "facebook.com",
    "instagram.com", "twitter.com", "whatsapp.com", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "coursera.org", "hackerrank.com", "leetcode.com", "kaggle.com"
]

# Free hosting, tunnels, and user-generated content roots where subdomains should not inherit trust
DYNAMIC_SUBDOMAIN_ROOTS = {
    "firebaseapp.com", "web.app", "weebly.com", "wixsite.com", "000webhostapp.com",
    "duckdns.org", "ngrok.io", "ngrok-free.app", "pages.dev", "workers.dev",
    "glitch.me", "herokuapp.com", "vercel.app", "netlify.app", "github.io"
}

# Homoglyph confusion dictionary: Cyrillic/Greek lookalikes mapped to Latin
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u03bf': 'o',
    '\u03c1': 'p', '\u03b1': 'a', '\u03bd': 'v', '\u0455': 's', '\u04cf': 'l'
}


def _levenshtein_distance(s1, s2):
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_homoglyph_attack(domain):
    """
    Detects internationalized domain names (IDN / punycode) or Unicode homoglyphs
    masquerading as standard Latin characters.
    """
    if not domain:
        return False, None

    domain_lower = domain.lower()

    # Punycode check
    if "xn--" in domain_lower:
        try:
            decoded = domain_lower.encode("ascii").decode("idna")
            return True, {
                "type": "PUNYCODE_IDN",
                "decoded": decoded,
                "description": f"Domain uses punycode encoding ({domain_lower} -> {decoded})"
            }
        except Exception:
            return True, {
                "type": "PUNYCODE_IDN",
                "decoded": domain_lower,
                "description": f"Domain contains punycode marker 'xn--'"
            }

    # Direct Unicode check against Latin lookalikes
    has_confusables = False
    normalized = []
    for char in domain_lower:
        if char in HOMOGLYPH_MAP:
            has_confusables = True
            normalized.append(HOMOGLYPH_MAP[char])
        else:
            normalized.append(char)

    if has_confusables:
        return True, {
            "type": "UNICODE_HOMOGLYPH",
            "normalized": "".join(normalized),
            "description": f"Domain contains mixed-script Unicode homoglyphs visually imitating Latin text."
        }

    return False, None


def detect_lookalike_domain(domain):
    """
    Checks if a domain is a deceptive lookalike / typosquat of high-profile target brands.
    Uses Levenshtein edit distance and common character substitution patterns (0->o, 1->l, etc.).
    """
    if not domain:
        return False, None

    root = get_root_domain(domain.lower())

    # Check homoglyph first
    is_homo, homo_info = detect_homoglyph_attack(root)
    if is_homo:
        # Check if the normalized string matches a target brand
        norm = homo_info.get("normalized", "")
        for target in REFERENCE_TARGET_DOMAINS:
            if norm == target:
                return True, {
                    "type": "HOMOGLYPH_IMPERSONATION",
                    "target_brand": target,
                    "suspicious_domain": root,
                    "description": f"Domain '{root}' is a Unicode homoglyph attack impersonating '{target}'."
                }

    # Levenshtein distance check on root domain names (excluding TLD)
    root_base = root.split(".")[0] if "." in root else root

    for target in REFERENCE_TARGET_DOMAINS:
        if root == target:
            # It's the actual legitimate domain, not a lookalike
            return False, None

        target_base = target.split(".")[0]

        # Common l33tspeak substitutions (paypa1 -> paypal, micros0ft -> microsoft)
        substituted = root_base.replace("0", "o").replace("1", "l").replace("vv", "w")
        if substituted == target_base and root_base != target_base:
            return True, {
                "type": "LEETSPEAK_TYPOSQUAT",
                "target_brand": target,
                "suspicious_domain": root,
                "description": f"Domain '{root}' uses number/letter substitution to impersonate '{target}'."
            }

        # Edit distance: distance of 1 on domain base of length >= 4 indicates targeted typosquatting
        if len(target_base) >= 4 and abs(len(root_base) - len(target_base)) <= 1:
            dist = _levenshtein_distance(root_base, target_base)
            if dist == 1:
                return True, {
                    "type": "TYPOSQUAT_LOOKALIKE",
                    "target_brand": target,
                    "suspicious_domain": root,
                    "description": f"Domain '{root}' is a visual lookalike (distance 1) targeting '{target}'."
                }

    return False, None


class DomainReputationStore:
    """Manages persistent observed domain history and user trust/block preferences."""

    def __init__(self, storage_path=REPUTATION_FILE):
        self.storage_path = storage_path
        self._ensure_storage()

    def _ensure_storage(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        if not os.path.exists(self.storage_path):
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump({"domains": {}, "user_rules": {}}, f, indent=2)

    def _read_data(self):
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"domains": {}, "user_rules": {}}

    def _write_data(self, data):
        try:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Sentinel Reputation Error] Failed to write data: {e}")

    def get_domain_info(self, domain):
        """Returns recorded reputation history and user rules for a domain."""
        if not domain:
            return None
        domain = domain.lower()
        root = get_root_domain(domain)
        data = self._read_data()

        user_override = data.get("user_rules", {}).get(root) or data.get("user_rules", {}).get(domain)
        history = data.get("domains", {}).get(root) or data.get("domains", {}).get(domain)

        return {
            "domain": domain,
            "root_domain": root,
            "user_override": user_override.get("status") if user_override else "NONE",
            "user_notes": user_override.get("notes") if user_override else "",
            "history": history
        }

    def set_user_rule(self, domain, status, notes=""):
        """Sets a user override: 'TRUSTED', 'BLOCKED', or 'NONE'."""
        if not domain:
            return False
        status = status.upper()
        if status not in ("TRUSTED", "BLOCKED", "NONE"):
            raise ValueError("status must be TRUSTED, BLOCKED, or NONE")

        domain = get_root_domain(domain.lower())
        data = self._read_data()
        user_rules = data.setdefault("user_rules", {})

        if status == "NONE":
            if domain in user_rules:
                del user_rules[domain]
        else:
            user_rules[domain] = {
                "status": status,
                "notes": notes,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

        self._write_data(data)
        return True

    def record_observation(self, domain, is_clean=True, spf_passed=True, dkim_passed=True):
        """Records observed interaction history for a domain without blindly trusting it."""
        if not domain:
            return
        root = get_root_domain(domain.lower())
        data = self._read_data()
        domains = data.setdefault("domains", {})

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = domains.get(root, {
            "first_seen": now,
            "last_seen": now,
            "total_seen": 0,
            "clean_count": 0,
            "threat_count": 0,
            "spf_passes": 0,
            "dkim_passes": 0
        })

        entry["last_seen"] = now
        entry["total_seen"] += 1
        if is_clean:
            entry["clean_count"] += 1
        else:
            entry["threat_count"] += 1

        if spf_passed:
            entry["spf_passes"] += 1
        if dkim_passed:
            entry["dkim_passes"] += 1

        domains[root] = entry
        self._write_data(data)


# Global singleton instance
reputation_store = DomainReputationStore()


def analyze_universal_sender_reputation(sender_domain, display_name="", auth_data=None):
    """
    Universal sender reputation analysis. Works on ANY domain (known, unseen, small business, global).
    Evaluates:
    - User trust / block preferences
    - Lookalike typosquatting and homoglyph attacks
    - Subdomain dynamics
    - Authentication status (gracefully handles missing auth without penalizing)
    """
    if not sender_domain:
        return {
            "reputation_status": "UNKNOWN",
            "is_user_trusted": False,
            "is_user_blocked": False,
            "is_lookalike": False,
            "lookalike_info": None,
            "is_dynamic_host": False,
            "reputation_score": 50,
            "evidence": []
        }

    sender_domain = sender_domain.lower()
    root_domain = get_root_domain(sender_domain)
    auth = auth_data or {}
    evidence = []

    # 1. User Overrides (Highest priority, user-controlled)
    info = reputation_store.get_domain_info(sender_domain)
    user_status = info["user_override"] if info else "NONE"

    is_user_trusted = user_status == "TRUSTED"
    is_user_blocked = user_status == "BLOCKED"

    if is_user_trusted:
        evidence.append({
            "type": "USER_TRUSTED_DOMAIN",
            "severity": "INFO",
            "description": f"Domain '{root_domain}' is explicitly marked as Trusted by user settings."
        })
    elif is_user_blocked:
        evidence.append({
            "type": "USER_BLOCKED_DOMAIN",
            "severity": "CRITICAL",
            "description": f"Domain '{root_domain}' is explicitly blocked by user settings."
        })

    # 2. Lookalike / Homoglyph / Typosquatting Check
    is_lookalike, lookalike_info = detect_lookalike_domain(sender_domain)
    if is_lookalike:
        evidence.append({
            "type": "LOOKALIKE_DOMAIN",
            "severity": "CRITICAL",
            "description": lookalike_info["description"]
        })

    # 3. Dynamic Subdomain / Free Tunnel Check
    is_dynamic_host = root_domain in DYNAMIC_SUBDOMAIN_ROOTS
    if is_dynamic_host:
        evidence.append({
            "type": "DYNAMIC_HOST_PROVIDER",
            "severity": "LOW",
            "description": f"Domain uses public shared hosting/tunnel infrastructure ({root_domain})."
        })

    # 4. Authentication Integration (Graceful handling of missing auth)
    spf = str(auth.get("spf") or "").lower()
    dkim = str(auth.get("dkim") or "").lower()

    if spf == "pass" and dkim == "pass":
        evidence.append({
            "type": "AUTH_AUTHENTICATED",
            "severity": "INFO",
            "description": f"Cryptographic sender authentication passed (SPF & DKIM valid for {root_domain})."
        })
    elif spf in ("fail", "permerror") or dkim == "fail":
        evidence.append({
            "type": "AUTH_FAILED",
            "severity": "HIGH",
            "description": f"Cryptographic authentication failed (SPF: {spf or 'none'}, DKIM: {dkim or 'none'})."
        })
    elif spf == "none" and dkim == "none":
        # Missing auth: completely normal for many legitimate independent websites and small senders
        evidence.append({
            "type": "AUTH_NEUTRAL",
            "severity": "INFO",
            "description": f"Standard unauthenticated sender ({root_domain}). Evaluated on content and behavior."
        })

    # 5. Calculate base structural reputation score (0-100)
    # 50 = Neutral/Unseen, 90 = User Trusted / Solid Auth, 10 = Lookalike / Blocked
    base_score = 50

    if is_user_trusted:
        base_score = 90
    elif is_user_blocked or is_lookalike:
        base_score = 10
    elif spf in ("fail", "permerror") or dkim == "fail":
        base_score = 25
    elif spf == "pass" and dkim == "pass":
        base_score = 75
    elif spf == "pass" or dkim == "pass":
        base_score = 65

    reputation_status = (
        "TRUSTED" if base_score >= 75
        else "BENIGN_NEUTRAL" if base_score >= 45
        else "SUSPICIOUS" if base_score >= 30
        else "HOSTILE"
    )

    return {
        "domain": sender_domain,
        "root_domain": root_domain,
        "reputation_status": reputation_status,
        "is_user_trusted": is_user_trusted,
        "is_user_blocked": is_user_blocked,
        "is_lookalike": is_lookalike,
        "lookalike_info": lookalike_info,
        "is_dynamic_host": is_dynamic_host,
        "reputation_score": base_score,
        "evidence": evidence
    }
