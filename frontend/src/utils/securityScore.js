/**
 * Sentinel AI — Canonical Threat Exposure & Risk Scoring Engine
 *
 * DESIGN & METHODOLOGY:
 * - Scale: 0 to 100.
 * - Meaning: HIGHER IS MORE DANGEROUS (0 = clean / likely safe, 100 = critical threat level).
 * - Bands:
 *   - 0–19: Low risk (Likely safe)
 *   - 20–39: Guarded (Needs caution)
 *   - 40–69: Suspicious
 *   - 70–100: High risk
 * - Threat Weighting & Accumulation:
 *   - Phishing / Critical threats: Contributes heavily to threat exposure (each confirmed incident immediately places channel in High Risk band >=70).
 *   - Needs Review / Suspicious: Places channel in Suspicious band (40-69).
 *   - Spam: Bulk commercial content places channel in Guarded band (20-39).
 * - Channel Scored Independently:
 *   - Gmail Score: based strictly on verified scanned emails.
 *   - SMS Score: based strictly on verified synced SMS messages.
 * - Integrity Guarantees:
 *   - If a channel is disconnected or has 0 messages, its score is strictly null.
 *   - UI displays "Not connected" or "Insufficient data", NEVER an invented score or default 0.
 *   - Overall score is the volume-weighted combination of ACTIVE channels.
 *   - A disconnected channel does NOT pull down or corrupt an active channel's score.
 */

export function calculateChannelScore({ total = 0, phishing = 0, review = 0, spam = 0, isConnected = false }) {
  if (!isConnected) return null;
  if (!total || total === 0) return null;

  // Normalized rates
  const phishingRate = phishing / total;
  const reviewRate = review / total;
  const spamRate = spam / total;

  if (phishing === 0 && review === 0 && spam === 0) {
    return 5; // Benign baseline (Low risk band: 0-19)
  }

  // Non-linear threat score calculation (0 to 100, where higher is more dangerous)
  let threatScore = 0;
  if (phishing > 0) {
    // Confirmed phishing immediately elevates channel into High Risk (>=70)
    threatScore = 70 + Math.min(25, (phishing - 1) * 5 + (phishingRate * 20));
  } else if (review > 0) {
    // Suspicious messages place channel in Suspicious band (40-69)
    threatScore = 40 + Math.min(25, (review - 1) * 4 + (reviewRate * 25));
  } else if (spam > 0) {
    // Unsolicited commercial content places channel in Guarded band (20-39)
    threatScore = 20 + Math.min(15, spamRate * 18);
  } else {
    threatScore = 5;
  }

  return Math.max(0, Math.min(100, Math.round(threatScore)));
}

export function calculateOverallScore({
  gmailScore = null,
  smsScore = null,
  totalEmails = 0,
  totalSms = 0
}) {
  if (gmailScore === null && smsScore === null) return null;
  if (gmailScore !== null && smsScore === null) return gmailScore;
  if (gmailScore === null && smsScore !== null) return smsScore;

  // Volume-weighted combination of active channels
  const gWeight = Math.max(1, totalEmails);
  const sWeight = Math.max(1, totalSms);
  return Math.round((gmailScore * gWeight + smsScore * sWeight) / (gWeight + sWeight));
}

export function getScoreStatus({ score = null, phishingCount = 0, reviewCount = 0 }) {
  if (score === null) {
    return {
      label: "Insufficient Data",
      verdict: "Unknown",
      variant: "badge-muted",
      explanation: "No verified communication telemetry available yet. Connect a channel to begin scanning."
    };
  }

  if (score >= 70 || phishingCount > 0) {
    return {
      label: "High Risk",
      verdict: "High risk",
      variant: "badge-danger",
      explanation: `${phishingCount} confirmed threat(s) detected. High risk detected. Do not open suspicious links or verify credentials.`
    };
  }

  if (score >= 40 || reviewCount > 0) {
    return {
      label: "Suspicious",
      verdict: "Suspicious",
      variant: "badge-amber",
      explanation: `${reviewCount} message(s) contain suspicious signals requiring analyst review.`
    };
  }

  if (score >= 20) {
    return {
      label: "Needs Caution",
      verdict: "Needs caution",
      variant: "badge-blue",
      explanation: "Guarded communication volume detected. Exercise routine verification for unexpected senders."
    };
  }

  return {
    label: "Likely Safe",
    verdict: "Likely safe",
    variant: "badge-success",
    explanation: "Communication channels exhibit authentic patterns with no active threat signals detected."
  };
}


