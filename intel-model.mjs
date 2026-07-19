// Shared intelligence classification and prioritization for the collector and browser.
// This module deliberately separates attribution from geography: a country mention may
// describe the sponsor, a victim, criminal nationality, or background context.

const CYBER_RX = /\b(cyber|hack(?:er|ers|ed|ing)?|malware|ransomware|wiper|phish(?:ing)?|botnet|backdoor|exploit(?:ed|ation|ing)?|vulnerabilit(?:y|ies)|zero[- ]day|espionage|spyware|credential|intrusion|breach|compromis(?:e|ed|ing)|command[- ]and[- ]control|\bc2\b|ddos|information warfare|disinformation|influence operation|hack[- ]and[- ]leak)\b/i;
const SPONSOR_RX = /\b(state[- ]sponsored|state[- ]backed|government[- ]backed|government[- ]sponsored|linked|aligned|nexus|attributed|suspected|affiliated|ties? to|operated by|intelligence service|military intelligence|cyber unit|threat actor|intrusion set|apt|cybersp(?:y|ies)|hackers?|campaign|operation)\b/i;
const VICTIM_RX = /\b(targets?|targeting|targeted|against|victims?|hit|breached|compromised|infected|attacked|impacted)\b/i;
const CRIMINAL_RX = /\b(cybercriminal|criminal|fraudster|ransomware gang|indicted|arrested|tourist|national|financially motivated|bulletproof hosting|stolen funds|cryptocurrency theft)\b/i;
const IMPACT_TERMS = [
  [22, "destructive effects", /\b(wiper|destructive attack|operational technology|\bot\b|industrial control|\bics\b)\b/i],
  [20, "critical-infrastructure targeting", /\b(critical infrastructure|power grid|energy sector|water utility|telecommunications?|healthcare)\b/i],
  [18, "active exploitation", /\b(zero[- ]day|actively exploited|in the wild|mass exploitation)\b/i],
  [16, "material intrusion impact", /\b(data theft|exfiltrat|service disruption|supply[- ]chain compromise|credential theft)\b/i],
  [12, "influence or information operation", /\b(disinformation|influence operation|hack[- ]and[- ]leak|propaganda)\b/i],
];

const AUTHORITY_RX = /\b(cisa|ncsc|cert[- ]?eu|jpcert|acsc|microsoft security|unit 42|talos|mandiant|google threat intelligence|crowdstrike|eset|proofpoint)\b/i;

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function termRegex(terms) {
  if (!terms.length) return null;
  return new RegExp(`\\b(${terms.map(escapeRegex).join("|")})\\b`, "gi");
}

function evidenceWindow(text, index, length, radius = 105) {
  return text.slice(Math.max(0, index - radius), Math.min(text.length, index + length + radius)).replace(/\s+/g, " ").trim();
}

function isNeutralNationalityUse(window, matchedTerm) {
  const term = escapeRegex(matchedTerm);
  return new RegExp(`\\b${term}\\s+(cybersecurity|security|software|technology|research|company|firm|vendor|researcher|tourist|national)s?\\b`, "i").test(window);
}

function victimRelationship(window, matchedTerm) {
  const term = escapeRegex(matchedTerm);
  const before = new RegExp(`\\b(targets?|targeting|against|hit|breached|compromised|infected|attacked)\\b[^.!?]{0,80}\\b${term}\\b`, "i");
  const after = new RegExp(`\\b${term}\\b[^.!?]{0,80}\\b(organizations?|agencies|government|companies|networks?|systems?|users?|victims?)\\b[^.!?]{0,50}\\b(targeted|hit|breached|compromised|infected|attacked)\\b`, "i");
  return before.test(window) || after.test(window);
}

function sponsorRelationship(window, matchedTerm) {
  const term = escapeRegex(matchedTerm);
  const after = new RegExp(`\\b${term}\\b[^.!?]{0,45}\\b(state[- ]sponsored|state[- ]backed|government[- ]backed|government[- ]sponsored|intelligence service|military intelligence|cyber unit|threat actor)\\b`, "i");
  const before = new RegExp(`\\b(state[- ]sponsored|state[- ]backed|government[- ]backed|government[- ]sponsored|attributed to|linked to)\\b[^.!?]{0,45}\\b${term}\\b`, "i");
  return after.test(window) || before.test(window);
}

function activityType(text) {
  if (/\b(disinformation|influence operation|propaganda|hack[- ]and[- ]leak)\b/i.test(text)) return "information-operation";
  if (/\b(ransomware|financially motivated|cybercriminal|cryptocurrency theft|bank heist|fraud)\b/i.test(text)) return "cybercrime";
  if (/\b(wiper|destructive|disruptive|sabotage)\b/i.test(text)) return "disruptive-operation";
  if (/\b(espionage|intelligence collection|data theft|credential theft)\b/i.test(text)) return "espionage";
  if (/\b(vulnerability|exploit|zero[- ]day|actively exploited)\b/i.test(text)) return "exploitation";
  return "cyber-activity";
}

function relationshipRank(value) {
  return { sponsor: 4, victim: 3, criminal: 2, context: 1 }[value] || 0;
}

function confidenceRank(value) {
  return { high: 3, medium: 2, low: 1 }[value] || 0;
}

export function buildRelationshipClassifier(countries, weakTerms = []) {
  const weak = new Set(weakTerms);
  const models = Object.entries(countries).map(([country, config]) => {
    const genericTerms = [...new Set([config.name, ...(config.genericTerms || [])])];
    const genericKeys = new Set(genericTerms.map((term) => term.toLowerCase()));
    const actorTerms = (config.terms || []).filter((term) => !genericKeys.has(term.toLowerCase()));
    return {
      country,
      genericRx: termRegex(genericTerms),
      actorRx: termRegex(actorTerms),
      weakActorRx: termRegex(actorTerms.filter((term) => weak.has(term))),
    };
  });

  return (title = "", summary = "") => {
    const titleText = String(title);
    const summaryText = String(summary);
    const text = `${titleText}. ${summaryText}`;
    const hasCyberCue = CYBER_RX.test(text);
    const relationships = [];

    for (const model of models) {
      const candidates = [];
      const actorMatches = model.actorRx ? [...text.matchAll(model.actorRx)] : [];
      for (const match of actorMatches) {
        const term = match[0];
        const inTitle = (match.index || 0) < titleText.length + 2;
        if (weak.has(term) && !inTitle) continue;
        candidates.push({
          country: model.country,
          relationship: "sponsor",
          confidence: inTitle ? "high" : "medium",
          evidence: evidenceWindow(text, match.index || 0, term.length),
        });
      }

      const genericMatches = model.genericRx ? [...text.matchAll(model.genericRx)] : [];
      for (const match of genericMatches) {
        const term = match[0];
        const window = evidenceWindow(text, match.index || 0, term.length);
        // A generic geography is only meaningful here when the report is about
        // cyber/IW activity or explicitly says it is state-sponsored. Named
        // actor aliases are sufficiently specific and are handled above.
        if (!hasCyberCue && !sponsorRelationship(window, term)) continue;
        const inTitle = (match.index || 0) < titleText.length + 2;
        if (isNeutralNationalityUse(window, term) && !CRIMINAL_RX.test(window)) continue;
        let relationship = null;
        let confidence = "low";
        if (sponsorRelationship(window, term)) {
          relationship = "sponsor";
          confidence = inTitle ? "high" : "medium";
        } else if (victimRelationship(window, term)) {
          relationship = "victim";
          confidence = inTitle ? "high" : "medium";
        } else if (CRIMINAL_RX.test(window)) {
          relationship = "criminal";
          confidence = "medium";
        } else if (SPONSOR_RX.test(window)) {
          relationship = "sponsor";
          confidence = inTitle ? "high" : "medium";
        } else if (inTitle && CYBER_RX.test(titleText)) {
          relationship = "context";
          confidence = "low";
        }
        if (relationship) candidates.push({ country: model.country, relationship, confidence, evidence: window });
      }

      candidates.sort((a, b) => relationshipRank(b.relationship) - relationshipRank(a.relationship)
        || confidenceRank(b.confidence) - confidenceRank(a.confidence));
      if (candidates[0]) relationships.push(candidates[0]);
    }

    return {
      relevant: relationships.length > 0,
      relationships,
      activityType: hasCyberCue ? activityType(text) : relationships.length ? "attributed-activity" : "other",
    };
  };
}

// Compatibility wrapper used by older integrations and focused unit tests.
export function buildClassifier(countries, weakTerms = []) {
  const classify = buildRelationshipClassifier(countries, weakTerms);
  return (title, summary) => classify(title, summary).relationships.map((item) => item.country);
}

export function parseSeenDate(value) {
  const text = String(value || "");
  if (/^\d{14}$/.test(text)) {
    return new Date(`${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`);
  }
  return new Date(text);
}

export function scoreArticle(article, options = {}) {
  const now = options.now || Date.now();
  const date = parseSeenDate(article.seendate);
  const ageDays = Number.isNaN(date.getTime()) ? 30 : Math.max(0, Math.floor((now - date.getTime()) / 86_400_000));
  const text = `${article.title || ""} ${article.summary || ""}`;
  const reasons = [];
  let score = ageDays === 0 ? 24 : ageDays <= 2 ? 20 : ageDays <= 7 ? 14 : ageDays <= 14 ? 8 : 3;
  reasons.push(ageDays <= 2 ? "recent reporting" : ageDays <= 7 ? "reported this week" : "older reporting");

  const relationship = article.relationship || "context";
  if (relationship === "sponsor") { score += 18; reasons.push("explicit sponsor attribution"); }
  else if (relationship === "victim") { score += 7; reasons.push("tracked-state victim impact"); }
  else if (relationship === "criminal") { score += 4; reasons.push("tracked-state cybercrime link"); }

  if (article.confidence === "high") { score += 10; reasons.push("high-confidence relationship"); }
  else if (article.confidence === "medium") { score += 5; reasons.push("moderate-confidence relationship"); }

  for (const [points, reason, pattern] of IMPACT_TERMS) {
    if (pattern.test(text)) { score += points; reasons.push(reason); break; }
  }

  const cves = [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((value) => value.toUpperCase()))];
  const kevSet = options.kevSet || new Set();
  if (cves.some((cve) => kevSet.has(cve))) { score += 18; reasons.push("CISA KEV match"); }
  if (AUTHORITY_RX.test(`${article.sourceCountry || ""} ${article.domain || ""}`)) { score += 10; reasons.push("authoritative source"); }

  const bounded = Math.min(100, score);
  return {
    score: bounded,
    level: bounded >= 70 ? "Priority" : bounded >= 48 ? "Monitor" : "Context",
    cssClass: bounded >= 70 ? "high" : bounded >= 48 ? "medium" : "info",
    reasons: [...new Set(reasons)].slice(0, 6),
  };
}

export function relationshipLabel(relationship) {
  return {
    sponsor: "Attributed sponsor",
    victim: "Victim geography",
    criminal: "Cybercrime link",
    context: "Country context",
  }[relationship] || "Country context";
}
