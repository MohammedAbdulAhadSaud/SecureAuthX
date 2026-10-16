/**
 * SecureAuthX — trackers.js
 *
 * A local, static signature list of commonly-embedded tracking/analytics
 * services, matched against third-party script/iframe hostnames already
 * gathered by the content script. This is NOT a live threat-intel feed —
 * it's a hand-maintained list covering the most common real-world
 * trackers, intentionally scoped (see README "Scope Decisions").
 */

const TRACKER_SIGNATURES = [
  { match: /google-analytics\.com|googletagmanager\.com\/gtag|analytics\.google\.com/, name: "Google Analytics", category: "Analytics" },
  { match: /googletagmanager\.com/, name: "Google Tag Manager", category: "Tag Management" },
  { match: /doubleclick\.net|googlesyndication\.com|googleadservices\.com/, name: "Google Ads", category: "Advertising" },
  { match: /connect\.facebook\.net|facebook\.com\/tr/, name: "Facebook Pixel", category: "Advertising" },
  { match: /clarity\.ms/, name: "Microsoft Clarity", category: "Session Recording" },
  { match: /hotjar\.com/, name: "Hotjar", category: "Session Recording" },
  { match: /omtrdc\.net|adobedtm\.com|demdex\.net/, name: "Adobe Analytics", category: "Analytics" },
  { match: /analytics\.tiktok\.com/, name: "TikTok Pixel", category: "Advertising" },
  { match: /snap\.licdn\.com|px\.ads\.linkedin\.com/, name: "LinkedIn Insight", category: "Advertising" },
  { match: /static\.ads-twitter\.com|analytics\.twitter\.com|t\.co\/i\/adsct/, name: "Twitter/X Pixel", category: "Advertising" },
  { match: /segment\.(com|io)/, name: "Segment", category: "Analytics" },
  { match: /mixpanel\.com/, name: "Mixpanel", category: "Analytics" },
  { match: /amplitude\.com/, name: "Amplitude", category: "Analytics" },
  { match: /fullstory\.com/, name: "FullStory", category: "Session Recording" },
  { match: /intercom\.io|intercomcdn\.com/, name: "Intercom", category: "Support/Chat (tracking-capable)" },
  { match: /crisp\.chat/, name: "Crisp Chat", category: "Support/Chat (tracking-capable)" },
  { match: /sentry\.io/, name: "Sentry", category: "Error Monitoring (not user-tracking)" },
  { match: /cloudflareinsights\.com/, name: "Cloudflare Web Analytics", category: "Analytics" },
  { match: /bat\.bing\.com/, name: "Microsoft Advertising (UET)", category: "Advertising" },
  { match: /pinterest\.com\/ct|pintrk/, name: "Pinterest Tag", category: "Advertising" },
];

/**
 * @param {string[]} hostnames third-party script/iframe hostnames from the page
 * @returns {{ host: string, name: string, category: string }[]}
 */
export function matchTrackers(hostnames) {
  const results = [];
  const seenNames = new Set();
  for (const host of hostnames) {
    for (const sig of TRACKER_SIGNATURES) {
      if (sig.match.test(host)) {
        const key = sig.name;
        if (!seenNames.has(key)) {
          seenNames.add(key);
          results.push({ host, name: sig.name, category: sig.category });
        }
        break;
      }
    }
  }
  return results;
}
