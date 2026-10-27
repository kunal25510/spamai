"""
Sentinel Security Agent - Enhanced Universal Security Rules & Forward Chaining Engine
Accurately distinguishes legitimate messages across all domains and industries from
phishing, brand impersonation, lookalike domains, and spam.
"""

import re
from trusted_domains import (
    extract_email_address,
    extract_domain,
    get_root_domain,
    is_trusted_domain,
    check_brand_impersonation,
    parse_url_details,
    check_mismatched_url
)
from domain_reputation import (
    analyze_universal_sender_reputation,
    detect_lookalike_domain
)


def extract_facts(email_input):
    """
    Extracts structured security facts from an email input across ANY domain.
    Accepts either a dict containing full email metadata or a raw string (for backward compatibility).
    """
    facts = set()
    evidence_details = []

    # Normalize input
    if isinstance(email_input, dict):
        email_data = email_input
        raw_text = (
            (email_data.get("subject") or "") + " " +
            (email_data.get("snippet") or "") + " " +
            (email_data.get("body") or "") + " " +
            (email_data.get("text") or "")
        ).strip()
        from_header = email_data.get("from") or ""
        reply_to = email_data.get("reply_to") or ""
        return_path = email_data.get("return_path") or ""
        auth_data = email_data.get("auth") or {}
        urls_input = email_data.get("urls") or []
    else:
        raw_text = str(email_input or "")
        email_data = {}
        from_header = ""
        reply_to = ""
        return_path = ""
        auth_data = {}
        urls_input = []

    text_lower = raw_text.lower()

    # 1. SENDER DOMAIN AND REPUTATION ANALYSIS
    display_name, sender_email = extract_email_address(from_header)
    sender_domain = extract_domain(sender_email)

    if not sender_domain:
        from_match = re.search(r'(?:from|sender):\s*([^<>\n\r]+<[^<>\n\r]+>|[^\s<>\n\r]+@[^\s<>\n\r]+)', raw_text, re.IGNORECASE)
        if from_match:
            display_name, sender_email = extract_email_address(from_match.group(1))
            sender_domain = extract_domain(sender_email)

    sender_root = get_root_domain(sender_domain)

    # Universal Sender Reputation Analysis
    rep_result = analyze_universal_sender_reputation(sender_domain, display_name, auth_data)

    if rep_result["is_user_trusted"]:
        facts.add("user_trusted_domain")
        evidence_details.extend(rep_result["evidence"])
    elif rep_result["is_user_blocked"]:
        facts.add("user_blocked_domain")
        evidence_details.extend(rep_result["evidence"])

    if rep_result["is_lookalike"]:
        facts.add("lookalike_domain_detected")
        evidence_details.append({
            "type": "LOOKALIKE_DOMAIN",
            "severity": "CRITICAL",
            "description": rep_result["lookalike_info"]["description"]
        })

    # Authentication status
    spf_status = str(auth_data.get("spf") or "").lower()
    dkim_status = str(auth_data.get("dkim") or "").lower()

    # Fallback to text inspection if structured auth was not provided
    if not spf_status:
        if "spf=pass" in text_lower or "received-spf: pass" in text_lower:
            spf_status = "pass"
        elif "spf=fail" in text_lower or "spf=softfail" in text_lower:
            spf_status = "fail"

    if not dkim_status:
        if "dkim=pass" in text_lower:
            dkim_status = "pass"
        elif "dkim=fail" in text_lower:
            dkim_status = "fail"

    if spf_status in ("fail", "permerror") or dkim_status in ("fail",):
        facts.add("auth_failed")
        evidence_details.append({
            "type": "AUTH_FAILED",
            "severity": "HIGH",
            "description": f"Email cryptographic authentication failed (SPF: {spf_status or 'none'}, DKIM: {dkim_status or 'none'})."
        })
    elif spf_status == "pass" and dkim_status == "pass":
        facts.add("auth_passed")
    elif spf_status == "none" and dkim_status == "none":
        # Missing auth: completely normal for many legitimate independent senders, colleges, or small companies.
        facts.add("auth_missing_neutral")

    # Threat context for brand evaluation
    has_threat_context = (
        ("auth_failed" in facts) or
        ("lookalike_domain_detected" in facts) or
        bool(re.search(r'\b(password|pin|otp|passcode|account suspended|verify immediately|urgent action)\b', text_lower))
    )

    # Known Trusted Platform check (as an additional verification trait, not an exclusive whitelist)
    is_trusted_known, org_name = is_trusted_domain(sender_domain)
    if is_trusted_known and "auth_failed" not in facts:
        facts.add("verified_trusted_sender")
        evidence_details.append({
            "type": "VERIFIED_PLATFORM",
            "severity": "INFO",
            "description": f"Sender domain '{sender_domain}' matches verified organization ({org_name})."
        })

    # Universal Brand Impersonation & Domain Alignment Verification
    is_impersonating, brand_verif = check_brand_impersonation(display_name, sender_domain, has_threat_context=has_threat_context)
    if brand_verif:
        verif_status = brand_verif.get("status")
        if verif_status == "ALIGNED":
            facts.add("domain_aligned_sender")
        elif verif_status == "IMPERSONATION" and is_impersonating and "verified_trusted_sender" not in facts and not rep_result["is_user_trusted"]:
            facts.add("brand_impersonation")
            evidence_details.append({
                "type": "BRAND_IMPERSONATION",
                "severity": "HIGH",
                "description": brand_verif["description"]
            })
        elif verif_status == "UNVERIFIED" and not is_trusted_known:
            facts.add("domain_ownership_unverified")
            evidence_details.append({
                "type": "DOMAIN_UNVERIFIED",
                "severity": "INFO",
                "description": brand_verif["description"]
            })

    # Return-Path / Reply-To Mismatch against sender
    if reply_to and sender_domain:
        _, reply_email = extract_email_address(reply_to)
        reply_domain = extract_domain(reply_email)
        reply_root = get_root_domain(reply_domain)
        # Check if reply domain root and SLD differ from sender domain
        if reply_domain and reply_root != sender_root and not is_trusted_domain(reply_domain)[0]:
            if get_sld_base(reply_domain) != get_sld_base(sender_domain):
                facts.add("mismatched_reply_to")
                evidence_details.append({
                    "type": "MISMATCHED_REPLY_TO",
                    "severity": "MEDIUM",
                    "description": f"Reply-To domain '{reply_domain}' does not align with sender domain '{sender_domain}'."
                })

    # 2. URL EXTRACTION & ANALYSIS
    extracted_urls = list(urls_input)
    if not extracted_urls:
        raw_urls = re.findall(r'https?://[^\s<>"\')]+', raw_text)
        for u in set(raw_urls):
            extracted_urls.append({"href": u, "text": ""})

    has_suspicious_url = False
    for item in extracted_urls:
        href = item.get("href") or ""
        anchor_text = item.get("text") or ""
        parsed_url = parse_url_details(href)

        # Mismatched visible link anchor text vs actual destination
        is_mismatch, mismatch_info = check_mismatched_url(anchor_text, href)
        if is_mismatch:
            facts.add("mismatched_url")
            has_suspicious_url = True
            evidence_details.append({
                "type": "MISMATCHED_URL",
                "severity": "HIGH",
                "description": f"Link text shows '{mismatch_info['displayed_domain']}' but href points to '{mismatch_info['actual_domain']}'."
            })

        # Lookalike link destination (e.g. link goes to paypa1.com or unslop.com)
        is_link_lookalike, link_lookalike_info = detect_lookalike_domain(parsed_url["root_domain"])
        if is_link_lookalike:
            facts.add("lookalike_url_destination")
            has_suspicious_url = True
            evidence_details.append({
                "type": "LOOKALIKE_LINK",
                "severity": "CRITICAL",
                "description": f"Link destination '{parsed_url['host']}' is a lookalike domain targeting '{link_lookalike_info['target_brand']}'."
            })

        # Raw IP address in link
        if parsed_url["is_ip"]:
            facts.add("ip_address_url")
            has_suspicious_url = True
            evidence_details.append({
                "type": "IP_ADDRESS_URL",
                "severity": "HIGH",
                "description": f"Link destination uses a raw IP address ({parsed_url['host']}) instead of a registered domain."
            })

        # Deceptive subdomain
        if parsed_url["is_deceptive"]:
            facts.add("deceptive_subdomain")
            has_suspicious_url = True
            evidence_details.append({
                "type": "DECEPTIVE_SUBDOMAIN",
                "severity": "HIGH",
                "description": f"URL hostname '{parsed_url['host']}' deceptively imitates '{parsed_url['deceptive_target']}'."
            })

        # Disposable high-risk TLD
        if parsed_url["is_high_risk_tld"]:
            facts.add("high_risk_tld")
            has_suspicious_url = True
            evidence_details.append({
                "type": "HIGH_RISK_TLD",
                "severity": "MEDIUM",
                "description": f"Link uses disposable high-risk TLD (.{parsed_url['host'].split('.')[-1]})."
            })

        # Shortener
        if parsed_url["is_shortener"]:
            facts.add("url_shortener")
            evidence_details.append({
                "type": "URL_SHORTENER",
                "severity": "LOW",
                "description": f"Contains shortened URL ({parsed_url['host']}) concealing destination."
            })

    if has_suspicious_url:
        facts.add("suspicious_links_present")

    # 3. CONTEXTUAL CREDENTIAL & MALICIOUS INTENT ANALYSIS
    # Explicit credential solicitation (asking recipient to reply with or send secret passwords/PINs/OTPs)
    if re.search(r'\b(reply with|send (?:us |me )?your|email (?:us |me )?your|provide your)\s+(?:password|pin|otp|passcode|secret key|seed phrase)\b', text_lower):
        facts.add("explicit_credential_solicitation")
        evidence_details.append({
            "type": "CREDENTIAL_SOLICITATION",
            "severity": "CRITICAL",
            "description": "Message asks recipient to reply or transmit confidential password, PIN, or OTP directly."
        })

    # High-pressure urgency threatening immediate account loss
    if re.search(r'\b(account will be (?:blocked|suspended|closed|deleted|deactivated|terminated)|action required immediately|final warning)\b', text_lower) and \
       re.search(r'\b(within 24 hours|within 12 hours|immediately|today|act now)\b', text_lower):
        facts.add("urgent_threat")
        evidence_details.append({
            "type": "URGENT_ACCOUNT_THREAT",
            "severity": "HIGH",
            "description": "High-pressure urgency threatening account suspension or penalty within hours."
        })

    # Advance-fee fraud / Fake prize / Lottery scams
    if re.search(r'\b(you won|lottery|claim (?:your )?(?:prize|cash|reward)|transfer fee|processing fee to claim)\b', text_lower) and \
       re.search(r'\b(50000|100000|crore|dollars|lakh|free money|beneficiary|unclaimed)\b', text_lower):
        facts.add("financial_scam_lure")
        evidence_details.append({
            "type": "FINANCIAL_SCAM",
            "severity": "HIGH",
            "description": "Unrealistic lottery, reward, or advance-fee prize solicitation."
        })

    # Fake job or internship charging money for offer letter
    if re.search(r'\b(internship|job offer|appointment letter)\b', text_lower) and \
       re.search(r'\b(registration fee|processing fee|security deposit|pay \d+|refundable fee)\b', text_lower):
        facts.add("fraudulent_fee_demand")
        evidence_details.append({
            "type": "JOB_FEE_SCAM",
            "severity": "HIGH",
            "description": "Demands upfront registration or processing fee for job or internship placement."
        })

    # Smishing / Delivery address & fee scams
    if re.search(r'\b(package|parcel|shipment|delivery|courier|fedex|dhl|usps|indiapost)\b', text_lower) and \
       re.search(r'\b(incomplete address|update address|wrong address|reschedule|held at warehouse|customs fee|pending fee)\b', text_lower) and \
       has_suspicious_url:
        facts.add("delivery_fee_scam")
        evidence_details.append({
            "type": "DELIVERY_SCAM",
            "severity": "HIGH",
            "description": "Smishing lure: fake package delivery issue directing recipient to unverified link."
        })

    # Fake KYC / SIM card deactivation threat (common SMS smishing)
    if re.search(r'\b(kyc|sim card|pan card|bank account|aadhaar|debit card)\b', text_lower) and \
       re.search(r'\b(suspended|blocked|deactivated|expire today|update immediately|within 24 hours)\b', text_lower):
        facts.add("kyc_account_threat")
        evidence_details.append({
            "type": "KYC_SCAM",
            "severity": "HIGH",
            "description": "Urgent SMS threat claiming immediate SIM, KYC, or account deactivation."
        })

    # Fraudulent UPI collect / refund scam
    if re.search(r'\b(refund of|cashback of|receive money|collect request|approve request|upi pin to receive|scan qr to receive)\b', text_lower) and \
       re.search(r'\b(inr|rs\.?|₹|\$|50000|100000|crore|lakh|\d+)\b', text_lower):
        facts.add("upi_payment_scam")
        evidence_details.append({
            "type": "UPI_REFUND_SCAM",
            "severity": "CRITICAL",
            "description": "Fraudulent UPI refund or payment approval lure (demands action/PIN to receive money)."
        })

    # Remote access software installation request (AnyDesk, TeamViewer, RustDesk)
    if re.search(r'\b(anydesk|teamviewer|rustdesk|quicksupport|ultraviewer)\b', text_lower) and \
       re.search(r'\b(install|download|share code|give code|allow access|remote)\b', text_lower):
        facts.add("remote_access_fraud")
        evidence_details.append({
            "type": "REMOTE_ACCESS_FRAUD",
            "severity": "CRITICAL",
            "description": "Requests installation of remote-control software enabling unauthorized device takeover."
        })

    # Genuine OTP / Verification Code notification (explicitly stating do not share)
    if re.search(r'\b(is your otp|otp is|verification code is|security code is|one time password)\b', text_lower) and \
       not re.search(r'\b(reply with|send (?:us |me )?your|enter your password|email your)\b', text_lower):
        facts.add("benign_otp_notification")

    # Genuine Bank transaction debit/credit alert
    if re.search(r'\b(debited by|credited with|spent on card|inr \d+|rs\.? \d+|txn of|acct xx\d+|balance is)\b', text_lower) and \
       not has_suspicious_url and not re.search(r'\b(password|pin|otp)\b', text_lower):
        facts.add("benign_bank_alert")

    # Genuine Delivery status update
    if re.search(r'\b(out for delivery|arriving today|has been delivered|with delivery associate)\b', text_lower) and \
       not re.search(r'\b(fee|pay|update address|blocked|suspended)\b', text_lower):
        facts.add("benign_delivery_update")

    # Ordinary Personal / Conversational message
    if re.search(r'\b(are we still|happy birthday|see you|call me|meet for|lunch|dinner|coffee|sounds good|thanks a lot|on my way|running late)\b', text_lower) and \
       not has_suspicious_url and not re.search(r'\b(password|pin|otp|login|verify|account|fee|prize)\b', text_lower):
        facts.add("personal_conversation")

    # Promotional / Marketing content (SMS & Email)
    if re.search(r'\b(unsubscribe|special discount|limited time deal|shop now|flat \d+% off|promotional message|clearance sale|exclusive offer|use code \w+)\b', text_lower):
        facts.add("promotional_content")

    # Benign transactional or service contexts from ANY website (orders, invoices, receipts, appointments, newsletters)
    if re.search(r'\b(invoice|receipt|order #|statement|booking|timetable|assignment|pull request|curriculum|scheduled for|appointment with|newsletter|monthly update|verification code|security code)\b', text_lower):
        facts.add("benign_service_context")

    # Deduplicate evidence_details while preserving insertion order
    seen_evidence = set()
    unique_evidence = []
    for ev in evidence_details:
        key = (ev.get("type"), ev.get("description"))
        if key not in seen_evidence:
            seen_evidence.add(key)
            unique_evidence.append(ev)

    return facts, unique_evidence


def forward_chain(facts):
    """
    Forward chaining reasoning engine that evaluates combinations of independent signals.
    Produces unambiguous security conclusions across any domain:
      - Legitimate Communication
      - Commercial Spam
      - Phishing Threat
      - Needs Review / Ambiguous
    """
    derived_facts = set(facts)
    changed = True

    while changed:
        changed = False

        # Rule 0: User Overrides (Explicit User Control)
        if "user_trusted_domain" in derived_facts and "phishing_threat" not in derived_facts:
            if "legitimate_communication" not in derived_facts:
                derived_facts.add("legitimate_communication")
                changed = True

        if "user_blocked_domain" in derived_facts:
            if "blocked_threat" not in derived_facts:
                derived_facts.add("blocked_threat")
                changed = True

        # Rule 1: Definitive Phishing Threats (High-confidence malicious deception)
        if (
            "explicit_credential_solicitation" in derived_facts or
            "lookalike_domain_detected" in derived_facts or
            "lookalike_url_destination" in derived_facts or
            "delivery_fee_scam" in derived_facts or
            "kyc_account_threat" in derived_facts or
            "remote_access_fraud" in derived_facts or
            "upi_payment_scam" in derived_facts or
            ("brand_impersonation" in derived_facts and ("suspicious_links_present" in derived_facts or "urgent_threat" in derived_facts or "auth_failed" in derived_facts)) or
            ("mismatched_url" in derived_facts and ("urgent_threat" in derived_facts or "brand_impersonation" in derived_facts)) or
            ("urgent_threat" in derived_facts and ("auth_failed" in derived_facts or "high_risk_tld" in derived_facts or "suspicious_links_present" in derived_facts or "url_shortener" in derived_facts))
        ):
            if "phishing_threat" not in derived_facts:
                derived_facts.add("phishing_threat")
                changed = True

        # Rule 2: Financial Scam / Advance-Fee Phishing
        if "financial_scam_lure" in derived_facts or "fraudulent_fee_demand" in derived_facts or "upi_payment_scam" in derived_facts:
            if "financial_phishing" not in derived_facts:
                derived_facts.add("financial_phishing")
                changed = True

        # Rule 3: Universal Legitimate Communication (Requires absence of ALL threat indicators)
        if (
            "phishing_threat" not in derived_facts and
            "financial_phishing" not in derived_facts and
            "blocked_threat" not in derived_facts and
            "brand_impersonation" not in derived_facts and
            "lookalike_domain_detected" not in derived_facts and
            "lookalike_url_destination" not in derived_facts and
            "mismatched_url" not in derived_facts and
            "ip_address_url" not in derived_facts and
            "auth_failed" not in derived_facts and
            "suspicious_links_present" not in derived_facts and
            "urgent_threat" not in derived_facts and
            "high_risk_tld" not in derived_facts and
            "url_shortener" not in derived_facts
        ):
            if (
                "verified_trusted_sender" in derived_facts or
                "user_trusted_domain" in derived_facts or
                "domain_aligned_sender" in derived_facts or
                "benign_otp_notification" in derived_facts or
                "benign_bank_alert" in derived_facts or
                "benign_delivery_update" in derived_facts or
                "personal_conversation" in derived_facts or
                "auth_passed" in derived_facts or
                ("benign_service_context" in derived_facts and "promotional_content" not in derived_facts) or
                ("domain_ownership_unverified" in derived_facts and "mismatched_reply_to" not in derived_facts)
            ):
                if "legitimate_communication" not in derived_facts:
                    derived_facts.add("legitimate_communication")
                    changed = True

        # Rule 4: Commercial / Promotional Spam
        # Promotional content from unverified senders without phishing threats or malicious links
        if (
            "promotional_content" in derived_facts and
            "legitimate_communication" not in derived_facts and
            "phishing_threat" not in derived_facts and
            "financial_phishing" not in derived_facts and
            "blocked_threat" not in derived_facts and
            "mismatched_url" not in derived_facts and
            "lookalike_domain_detected" not in derived_facts
        ):
            if "commercial_spam" not in derived_facts:
                derived_facts.add("commercial_spam")
                changed = True

        # Rule 5: Needs Review (Ambiguous / Conflicting / Unverified signals)
        # Conflicting signals or ambiguous traits that do not definitively prove phishing:
        # e.g., auth failure on unknown domain, unaligned reply-to, URL shortener with urgent tone, or mismatched URL without threat context
        if (
            "phishing_threat" not in derived_facts and
            "financial_phishing" not in derived_facts and
            "blocked_threat" not in derived_facts and
            "legitimate_communication" not in derived_facts and
            "commercial_spam" not in derived_facts and
            (
                "auth_failed" in derived_facts or
                "mismatched_url" in derived_facts or
                "brand_impersonation" in derived_facts or
                "deceptive_subdomain" in derived_facts or
                ("url_shortener" in derived_facts and "urgent_threat" in derived_facts) or
                "mismatched_reply_to" in derived_facts or
                "domain_ownership_unverified" in derived_facts
            )
        ):
            if "needs_review" not in derived_facts:
                derived_facts.add("needs_review")
                changed = True

    return derived_facts