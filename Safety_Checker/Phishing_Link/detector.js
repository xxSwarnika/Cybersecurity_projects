/**
 * Phishing URL Detector
 *
 * Analyses a URL with heuristics commonly used to spot phishing links.
 * Everything runs locally: the URL is never visited or sent anywhere.
 *
 * Works in the browser (window.PhishingDetector) and in Node (module.exports).
 */
(function (root) {
  "use strict";

  // Brands that are often impersonated, with their real registered domains.
  const BRANDS = {
    paypal: ["paypal.com"],
    apple: ["apple.com", "icloud.com"],
    icloud: ["icloud.com", "apple.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    office365: ["office.com", "microsoft.com"],
    outlook: ["outlook.com", "live.com", "office.com"],
    google: ["google.com", "google.no", "youtube.com"],
    gmail: ["google.com", "gmail.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.se"],
    netflix: ["netflix.com"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    linkedin: ["linkedin.com"],
    dropbox: ["dropbox.com"],
    docusign: ["docusign.com", "docusign.net"],
    dhl: ["dhl.com", "dhl.no"],
    fedex: ["fedex.com"],
    ups: ["ups.com"],
    posten: ["posten.no", "bring.no"],
    bring: ["bring.no", "bring.com"],
    dnb: ["dnb.no"],
    nordea: ["nordea.no", "nordea.com"],
    sparebank: ["sparebank1.no"],
    vipps: ["vipps.no"],
    bankid: ["bankid.no"],
    altinn: ["altinn.no"],
    nav: ["nav.no"],
    skatteetaten: ["skatteetaten.no"],
    finn: ["finn.no"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    steam: ["steampowered.com", "steamcommunity.com"],
  };

  // Top-level domains that show up disproportionately in abuse reports.
  const RISKY_TLDS = new Set([
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "fit", "loan", "men", "kim", "cam", "buzz", "icu",
    "monster", "cyou", "sbs", "quest", "live", "shop",
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly",
  ]);

  // Free hosting / site builders that phishers use to host fake login pages.
  const FREE_HOSTS = new Set([
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "pages.dev", "netlify.app", "vercel.app", "glitch.me", "github.io", "blogspot.com",
    "sites.google.com", "ngrok.io", "ngrok-free.app", "repl.co", "workers.dev",
  ]);

  const BAIT_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "password", "unlock", "suspended",
    "wallet", "billing", "invoice", "payment", "support", "recover", "validate",
  ];

  // Second-level suffixes, so "example.co.uk" is treated as one registered domain.
  const MULTI_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp",
    "com.br", "co.in", "co.za", "com.mx", "com.tr", "com.cn",
  ]);

  // ---------------------------------------------------------------- helpers

  function levenshtein(a, b) {
    if (a === b) return 0;
    const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      let diag = prev[0];
      prev[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const tmp = prev[j];
        prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
        diag = tmp;
      }
    }
    return prev[b.length];
  }

  // Undo the character swaps phishers use: paypa1 -> paypal, rnicrosoft -> microsoft.
  function deLeet(s) {
    return s
      .replace(/rn/g, "m")
      .replace(/vv/g, "w")
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/5/g, "s")
      .replace(/\$/g, "s")
      .replace(/@/g, "a");
  }

  function splitHost(host) {
    const labels = host.split(".");
    const lastTwo = labels.slice(-2).join(".");
    const take = MULTI_SUFFIXES.has(lastTwo) && labels.length > 2 ? 3 : 2;
    const registered = labels.slice(-take).join(".");
    const subdomain = labels.slice(0, -take).join(".");
    const tld = labels[labels.length - 1];
    const name = labels[labels.length - take]; // e.g. "paypal" in paypal.com
    return { registered, subdomain, tld, name, labels };
  }

  function isOfficialFor(brand, registered) {
    return BRANDS[brand].some((d) => registered === d || registered.endsWith("." + d));
  }

  function normaliseInput(raw) {
    let s = String(raw || "").trim();
    if (!s) throw new Error("Paste a URL to analyse.");
    if (/^(javascript|data|vbscript):/i.test(s)) return { special: s.split(":")[0].toLowerCase() };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "http://" + s; // no scheme given
    let url;
    try {
      url = new URL(s);
    } catch {
      throw new Error("That doesn't look like a valid URL. Check for typos and try again.");
    }
    return { url, original: String(raw).trim(), schemeGiven: /^[a-z][a-z0-9+.-]*:\/\//i.test(String(raw).trim()) };
  }

  // ---------------------------------------------------------------- analysis

  function analyze(raw) {
    const input = normaliseInput(raw);
    const findings = [];
    const add = (id, severity, points, title, detail) =>
      findings.push({ id, severity, points, title, detail });

    if (input.special) {
      add("script-scheme", "high", 60, `Uses the "${input.special}:" scheme`,
        "This isn't a web address. It can run code or show hidden content in your browser.");
      return finish(findings, null);
    }

    const { url, original, schemeGiven } = input;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const parts = splitHost(host);
    const full = original;

    // Protocol
    if (url.protocol === "http:" && schemeGiven) {
      add("no-https", "medium", 15, "Not encrypted (HTTP)",
        "Anything you type on this page, including passwords, is sent in plain text.");
    } else if (!["http:", "https:"].includes(url.protocol)) {
      add("odd-scheme", "medium", 15, `Unusual scheme "${url.protocol}"`, "Web pages normally use https.");
    }

    // IP address instead of domain
    const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const isIPv6 = host.startsWith("[");
    if (isIPv4 || isIPv6) {
      add("ip-host", "high", 30, "Uses an IP address instead of a domain name",
        "Real companies use their own domain. A bare IP address hides who runs the site.");
    }

    // @ trick: everything before @ is ignored by the browser
    if (url.username || url.password || /@/.test(full.split("?")[0].replace(/^[a-z]+:\/\//i, "").split("/")[0])) {
      add("at-sign", "high", 40, "Contains an @ before the domain",
        `Browsers ignore everything before the @. This link really goes to ${host}.`);
    }

    // Punycode / non-ASCII lookalike characters
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
      add("punycode", "high", 40, "Uses international lookalike characters (punycode)",
        "Letters from other alphabets can look identical to Latin ones, e.g. Cyrillic а instead of a.");
    }

    if (!isIPv4 && !isIPv6) {
      // Brand impersonation and typosquatting
      const brandHits = new Set();
      const regName = parts.name || "";
      const regClean = deLeet(regName.replace(/-/g, ""));

      for (const brand of Object.keys(BRANDS)) {
        if (isOfficialFor(brand, parts.registered)) continue;

        const inSub = parts.subdomain.split(/[.-]/).includes(brand);
        const inName = regName.split("-").includes(brand) || (regName.includes(brand) && regName !== brand);
        const inPath = new RegExp(`(^|[^a-z])${brand}([^a-z]|$)`).test((url.pathname + url.search).toLowerCase());

        if (inSub || inName) {
          brandHits.add(brand);
          add(`brand-${brand}`, "high", 40, `Mentions "${brand}" but isn't ${brand}'s website`,
            `The real domain is ${parts.registered}, not ${BRANDS[brand][0]}.`);
        } else if (inPath) {
          brandHits.add(brand);
          add(`brand-path-${brand}`, "medium", 15, `Mentions "${brand}" in the path`,
            `The page is on ${parts.registered}, which doesn't belong to ${brand}.`);
        }
      }

      // Typosquatting: domain name very close to a brand domain
      if (regName.length >= 4) {
        const seenReal = new Set();
        for (const brand of Object.keys(BRANDS)) {
          if (brandHits.has(brand) || isOfficialFor(brand, parts.registered)) continue;
          for (const real of BRANDS[brand]) {
            const realName = real.split(".")[0];
            if (seenReal.has(realName)) break;
            if (realName.length < 4 || regName === realName) continue;
            const d = Math.min(levenshtein(regName, realName), levenshtein(regClean, realName));
            const limit = realName.length >= 8 ? 2 : 1;
            if (d <= limit || regClean === realName) {
              brandHits.add(brand);
              seenReal.add(realName);
              add(`typo-${brand}`, "high", 50, `Looks like a misspelling of ${real}`,
                `"${parts.registered}" is only ${Math.max(d, 1)} character${d > 1 ? "s" : ""} away from the real site.`);
              break;
            }
          }
        }
      }

      // A real domain placed at the start, e.g. vipps.no.secure-login.ru
      if (parts.subdomain) {
        const fake = Object.values(BRANDS).flat().find((d) => (parts.subdomain + ".").includes(d + "."));
        if (fake && parts.registered !== fake) {
          add("domain-in-subdomain", "high", 35, `Starts with "${fake}" but goes somewhere else`,
            `The part that matters is at the end: this site is ${parts.registered}.`);
        }
      }

      // Risky TLD
      if (RISKY_TLDS.has(parts.tld)) {
        add("risky-tld", "medium", 12, `Uses the ".${parts.tld}" ending`,
          "This domain ending is cheap and frequently used for scam sites.");
      }

      // Many subdomains
      const subCount = parts.subdomain ? parts.subdomain.split(".").length : 0;
      if (subCount >= 3) {
        add("deep-subdomains", "medium", 15, `${subCount} levels of subdomains`,
          "Long chains of subdomains are used to push the real domain out of view.");
      }

      // Hyphens in the registered name
      const hyphens = regName.startsWith("xn--") ? 0 : (regName.match(/-/g) || []).length;
      if (hyphens >= 2) {
        add("hyphens", "low", 8, `Domain name has ${hyphens} hyphens`,
          "Names like secure-login-account.com are typical for throwaway phishing domains.");
      }

      // Shorteners and free hosting
      if (SHORTENERS.has(parts.registered) || SHORTENERS.has(host)) {
        add("shortener", "medium", 15, "Link shortener",
          "The real destination is hidden. Expand the link with a preview service before opening it.");
      }
      const freeHost = [...FREE_HOSTS].find((d) => host === d || host.endsWith("." + d));
      if (freeHost) {
        add("free-host", "medium", 15, `Hosted on a free platform (${freeHost})`,
          "Anyone can create a site here in minutes. Banks and big companies don't host logins on them.");
      }
    }

    // Bait words in host or path
    const haystack = (host + " " + url.pathname + " " + url.search).toLowerCase();
    const bait = BAIT_WORDS.filter((w) => haystack.includes(w));
    if (bait.length) {
      const pts = Math.min(5 * bait.length, 15);
      add("bait-words", bait.length >= 3 ? "medium" : "low", pts,
        `Pressure words: ${bait.slice(0, 5).join(", ")}`,
        "Phishing links often promise to verify, unlock or secure your account.");
    }

    // Length
    if (full.length > 100) {
      add("long-url", "low", 8, `Very long URL (${full.length} characters)`,
        "Long URLs make it harder to see where you're really going.");
    }

    // Non-standard port
    if (url.port && !["80", "443"].includes(url.port)) {
      add("port", "medium", 12, `Uses port ${url.port}`, "Normal websites don't need a special port.");
    }

    // Redirects hidden in the URL
    const redirectParam = [...url.searchParams.entries()].find(
      ([k, v]) => /^(url|u|q|redirect|redirect_uri|redir|next|return|returnurl|goto|dest|target|continue)$/i.test(k) && /^https?:|^\/\//i.test(v)
    );
    if (redirectParam) {
      add("redirect", "medium", 12, `Forwards you to another site (${redirectParam[0]}=)`,
        "Trusted sites can be abused to bounce you on to a malicious one.");
    }
    if (/\/\/.+\/\//.test(full.replace(/^[a-z]+:\/\//i, "//"))) {
      add("double-slash", "low", 6, "Extra // inside the path", "Can be a sign of a hidden redirect.");
    }

    // Heavy encoding
    const encoded = (full.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encoded >= 5) {
      add("encoding", "low", 8, `${encoded} encoded characters`,
        "Encoding can be used to hide words or characters from filters and readers.");
    }

    // Suspicious file downloads
    if (/\.(exe|scr|zip|rar|vbs|iso|apk|msi|bat|cmd)$/i.test(url.pathname)) {
      add("download", "medium", 15, "Links straight to a program or archive",
        "Opening this could download malware.");
    }

    return finish(findings, { url, host, parts, original });
  }

  function finish(findings, ctx) {
    const score = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
    let verdict, label;
    if (score >= 45) { verdict = "danger"; label = "Likely phishing"; }
    else if (score >= 15) { verdict = "warning"; label = "Suspicious"; }
    else { verdict = "safe"; label = "No obvious warning signs"; }

    findings.sort((a, b) => b.points - a.points);
    const segments = ctx ? {
      scheme: ctx.url.protocol.replace(":", ""),
      subdomain: ctx.parts.subdomain,
      registered: ctx.parts.registered,
      port: ctx.url.port,
      rest: ctx.url.pathname + ctx.url.search + ctx.url.hash,
    } : null;

    return { score, verdict, label, findings, host: ctx ? ctx.host : null, segments };
  }

  const api = { analyze, levenshtein, splitHost };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PhishingDetector = api;
})(typeof window !== "undefined" ? window : globalThis);
