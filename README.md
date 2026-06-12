# Big 4 Cyber & Information Warfare Threat Dashboard

A single-file, zero-build threat-intelligence dashboard focused on the **Big 4**
state cyber actors — **China (PRC), Russia, Iran, and North Korea (DPRK)**. It is
designed for COPC-style operational awareness and quick research triage, and it
**updates on demand** from public open-source feeds.

## Features

- **Country snapshot cards** for China, Russia, Iran, and North Korea, each
  showing live actor counts, news counts, and current focus areas.
- **Update on demand:**
  - **Refresh live news** — pulls current public reporting from the
    [GDELT Doc API](https://api.gdeltproject.org/api/v2/doc/doc), deduplicated and
    ranked by likely operational relevance, with a selectable 7/14/30/90-day lookback.
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
