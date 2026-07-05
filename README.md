# Big 4 Cyber & Information Warfare Threat Dashboard

A single-file, zero-build threat-intelligence dashboard focused on the **Big 4**
state cyber actors — **China (PRC), Russia, Iran, and North Korea (DPRK)**. It is
designed for COPC-style operational awareness and quick research triage, and it
**updates on demand** from public open-source feeds.

## Features

- **Country snapshot cards** for China, Russia, Iran, and North Korea, each
  showing live actor counts, news counts, and current focus areas.
- **Update on demand**, with a selectable **news source**:
  - **GDELT API** — pulls current public reporting from the
    [GDELT Doc API](https://api.gdeltproject.org/api/v2/doc/doc), deduplicated and
    ranked by likely operational relevance, with a selectable 7/14/30/90-day lookback.
  - **Google News** — runs the same per-country cyber query against the Google News
    RSS search endpoint, aggregating thousands of outlets with a `when:` recency
    window tied to the lookback selector.
  - **Cyber news feeds (RSS)** — reaches out to 23 sources: cyber-security press
    (The Hacker News, BleepingComputer, Krebs on Security, CyberScoop, SecurityWeek,
    Dark Reading, The Record, Help Net Security, The Register, WIRED), vendor
    threat-research blogs (Microsoft, Cisco Talos, Palo Alto
    Unit 42, CrowdStrike, SentinelOne, ESET, Kaspersky Securelist, Check Point,
    Fortinet, Proofpoint), and SANS ISC + CISA — keeping items
    mentioning China, Russia, Iran, or North Korea. Because most outlets don't send CORS headers,
    these requests are routed through a public CORS proxy; edit the feed list in
    `data/sources.json` (the single source of truth for both the hourly collector
    and the in-browser live fetch) to add or remove outlets.
  - **Refresh APT catalog** — live-loads CN/RU/IR/KP country-tagged actors from
    [MISP Galaxy](https://github.com/MISP/misp-galaxy) Threat Actor and Microsoft
    Activity Group data, merged with the built-in curated list.
- **APT / Actor catalog** with aliases, vendor naming, notes, and source links.
- **KEV tab** — the most recently added [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (CVE, vendor/product, due date, ransomware flag). Collected hourly into `data/kev.json`.
- **ATT&CK profiles** — each actor's known techniques and software from MITRE
  ATT&CK (refreshed daily into `data/attack.json`), with one-click **ATT&CK
  Navigator layer** export.
- **EPSS scores** — FIRST's exploit-probability score on every KEV entry
  (refreshed daily into `data/epss.json`).
- **IOC extraction** — hashes, IPs, CVEs, and published defanged indicators from
  any story (Diamond Model view), copied defanged for hunting.
- **Trends** — stories per country per day, charted from the rolling archive.
- **Analyst Workbench** — pin stories with notes, keep keyword watchlists
  (highlighted in Recent News); all localStorage, nothing leaves the browser.
- **Shareable deep links** — tab/filter/search state lives in the URL hash
  (e.g. `#tab=news&q=Salt%20Typhoon&c=CN`).
- **Machine-readable outputs** — `data/news.json` (curated stream), `feed.xml`
  (RSS 2.0 for readers), and on-demand **STIX 2.1 bundle** export for MISP/OpenCTI.
- **Copy brief** — one click exports the current (filtered) news as a dated,
  country-grouped Markdown brief (pinned stories lead), ready to paste into a
  daily/weekly writeup.
- **Filtering & search** by country and free text (actor names, aliases, news, CVEs).
- **Offline fallback** — a curated catalog of Big 4 actors ships in the page, so
  the dashboard remains useful with no network access.
- **Print-friendly** styling for briefs.

## Usage

This is a standalone HTML file — no build step or dependencies required.

**Option 1 — open directly:**

Open `index.html` in any modern browser.

**Option 2 — serve locally (recommended for live refresh):**

Some browsers block cross-origin `fetch` from `file://` URLs. Serving the file
avoids that:

```bash
python3 -m http.server 8000
# then visit http://localhost:8000/
```

Internet access is only required for the **live news** and **live actor catalog**
refresh. The curated fallback data works fully offline.

## Deployment (GitHub Pages)

The repo includes a GitHub Actions workflow (`.github/workflows/deploy.yml`) that
publishes the dashboard to GitHub Pages on every push to `main` (and on manual
**Run workflow**). Hosting it over `https://` also fixes the `file://` network
restrictions, so the live refresh works with no local server.

**One-time setup:** in the repo, go to **Settings → Pages → Build and deployment
→ Source** and select **GitHub Actions**. After the next push to `main`, the
**Deploy to GitHub Pages** workflow runs and the site is published at
`https://<owner>.github.io/cyber-threat-dashboard/`.

## Hourly news collector (recommended)

Fetching ~24 feeds from the browser depends on a public CORS proxy and can be
rate-limited. To avoid that, a scheduled GitHub Action collects the news
**server-side** instead:

- **`scripts/fetch-news.mjs`** — a dependency-free Node script that fetches every
  feed directly (no CORS/proxy), keeps Big-4-relevant items, and writes `data/news.json`.
- **`.github/workflows/sync-news.yml`** — runs the script **hourly** (and on manual
  **Run workflow**), commits `data/news.json` (plus `data/kev.json` and a rolling `data/archive.json` of daily counts), and redeploys Pages.

The dashboard's default source, **Hourly feed (prebuilt)**, reads `data/news.json`
same-origin — instant, no proxy, no rate limits — and loads automatically on open.
The live sources (GDELT, Google News, Cyber news feeds) remain available as an
on-demand fallback.

**To populate it the first time**, run the **Sync news feed** workflow once from
the **Actions** tab (it otherwise runs hourly). Until then, `data/news.json` ships as an
empty placeholder and the dashboard shows a hint to run the workflow.

A second scheduled workflow, **Sync enrichment data**
(`.github/workflows/sync-enrichment.yml`, daily), reduces the MITRE ATT&CK
enterprise STIX bundle to `data/attack.json` (group → techniques/software) and
fetches FIRST EPSS scores for the KEV slice into `data/epss.json`. Run it once
from the Actions tab to populate the ATT&CK profiles and EPSS column.

## Data sources

- MITRE ATT&CK enterprise STIX (group techniques/software) & FIRST EPSS
- MISP Galaxy Threat Actor & Microsoft Activity Group clusters
- Microsoft threat actor naming taxonomy (Typhoon / Blizzard / Sandstorm / Sleet)
- GDELT Doc API (news discovery)
- MITRE ATT&CK Groups, Malpedia, CISA advisories (reference links)

## Analytic caveats

"APT" naming is **not** standardized. Vendor names overlap, split, or merge over
time. Treat the catalog as an attribution/naming index, not a legal
determination. Attribution is probabilistic and based on TTPs, infrastructure,
malware, targeting, timing, language, and government/vendor reporting.
