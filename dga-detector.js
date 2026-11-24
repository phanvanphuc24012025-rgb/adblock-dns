// A lightweight heuristic to flag domains that LOOK machine-generated,
// the way a lot of malware/botnet command-and-control domains do
// (e.g. "xqzvpqoweiur.net"). This is a heuristic, not a certainty — it
// flags for logging/review by default rather than auto-blocking, to avoid
// false positives on legitimate but randomly-named services (CDNs, cloud
// storage buckets, etc).

// Shannon entropy: higher = more "random-looking" characters.
function entropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let sum = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    sum -= p * Math.log2(p);
  }
  return sum;
}

function digitRatio(str) {
  const digits = (str.match(/[0-9]/g) || []).length;
  return digits / str.length;
}

function consonantRunRatio(str) {
  // Long runs of consonants with no vowels is a common DGA fingerprint.
  const matches = str.match(/[bcdfghjklmnpqrstvwxyz]{5,}/gi);
  if (!matches) return 0;
  const total = matches.reduce((a, m) => a + m.length, 0);
  return total / str.length;
}

// Returns { suspicious: boolean, score: number, reasons: string[] }
function analyze(domain) {
  const clean = domain.toLowerCase().replace(/\.$/, '');
  const labels = clean.split('.');
  // Look at the "main" label (second-level domain), e.g. "xqzvpqoweiur"
  // in "xqzvpqoweiur.net" — that's usually where DGA randomness shows up.
  const label = labels.length >= 2 ? labels[labels.length - 2] : labels[0];

  if (!label || label.length < 8) {
    return { suspicious: false, score: 0, reasons: [] };
  }

  const reasons = [];
  let score = 0;

  const e = entropy(label);
  if (e > 3.5) {
    score += 2;
    reasons.push(`high entropy (${e.toFixed(2)})`);
  }

  const dRatio = digitRatio(label);
  if (dRatio > 0.3) {
    score += 1;
    reasons.push(`high digit ratio (${(dRatio * 100).toFixed(0)}%)`);
  }

  const cRatio = consonantRunRatio(label);
  if (cRatio > 0.4) {
    score += 1;
    reasons.push('long consonant runs');
  }

  if (label.length > 20) {
    score += 1;
    reasons.push(`unusually long label (${label.length} chars)`);
  }

  return { suspicious: score >= 3, score, reasons };
}

module.exports = { analyze, entropy };
