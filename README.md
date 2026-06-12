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
  - **Cyber news feeds (RSS)** — reaches out to major cyber-security outlets
    (Krebs on Security, BleepingComputer, The Hacker News, The Record, Dark Reading,
    SecurityWeek, SANS ISC, CISA) via their RSS feeds and keeps the items mentioning
    China, Russia, Iran, or North Korea. Because most outlets don't send CORS headers,
    these requests are routed through a public CORS proxy; edit the `CYBER_FEEDS` list
    in `index.html` to add or remove outlets.
  - **Refresh APT catalog** — live-loads CN/RU/IR/KP country-tagged actors from
    [MISP Galaxy](https://github.com/MISP/misp-galaxy) Threat Actor and Microsoft
    Activity Group data, merged with the built-in curated list.
- **APT / Actor catalog** with aliases, vendor naming, notes, and source links.
- **Filtering & search** by country and free text (actor names, aliases, news).
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

## Data sources

- MISP Galaxy Threat Actor & Microsoft Activity Group clusters
- Microsoft threat actor naming taxonomy (Typhoon / Blizzard / Sandstorm / Sleet)
- GDELT Doc API (news discovery)
- MITRE ATT&CK Groups, Malpedia, CISA advisories (reference links)

## Analytic caveats

"APT" naming is **not** standardized. Vendor names overlap, split, or merge over
time. Treat the catalog as an attribution/naming index, not a legal
determination. Attribution is probabilistic and based on TTPs, infrastructure,
malware, targeting, timing, language, and government/vendor reporting.
