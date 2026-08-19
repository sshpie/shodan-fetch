<h1 align="center">shodan-fetch</h1>

<h4 align="center">Authenticated Shodan harvest through a persistent browser session, zero API credits.</h4>

<p align="center">
  <a href="https://github.com/sshpie/shodan-fetch/blob/main/LICENSE"><img src="https://img.shields.io/github/license/sshpie/shodan-fetch?style=flat-square" alt="license"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python" alt="python"></a>
  <a href="https://playwright.dev"><img src="https://img.shields.io/badge/playwright-chromium-45ba4b?style=flat-square&logo=playwright" alt="playwright"></a>
  <a href="https://sshpie.com"><img src="https://img.shields.io/badge/by--blue?style=flat-square" alt=""></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#facet-and-host-modes">Facet & Host</a> •
  <a href="#output">Output</a> •
  <a href="#scope">Scope</a>
</p>

---

shodan-fetch harvests the Shodan web UI through a real logged-in browser session. It returns the same per-host data and facets the API would, without spending API query credits or a token. The method: one persistent Chrome profile holds the Shodan session cookie, an in-page `fetch()` call runs inside that session with `credentials: 'include'`, and the server-rendered HTML is parsed for result cards, facets, and country breakdowns. Assets (images, CSS, fonts, the map widget) never load, so each query is a single small round-trip instead of a 5 to 10 second full page render. Queries fan out in parallel via `Promise.all` inside the page context.

A batch of queries returns full host records in about 1 to 1.5 seconds, authenticated by the session cookie alone.

# Features

- Persistent Chrome profile holds a real Shodan login, reused across every run
- In-page `fetch()` rides the session cookie, no API token, no API query credits
- All queries and all pages of each query fire in parallel via `Promise.all`
- Parses server-rendered HTML directly (no hidden API, verified at DevTools)
- Single-query, multi-query (`--file dorks.txt`), and IP-only (`--ips-only`) output modes
- `--facet <fields>` returns full population distribution across any Shodan facet field (vuln, http.status, tag, ssl.version, plus ~85 more)
- `--host <ips>` returns per-IP dossier: every open port, web-tech fingerprint, tags, CVEs, General Information block
- Fails loud on expired sessions, never returns a silent empty result
- Pipes cleanly into `jaxen import --no-lookup` and `aimap -iL`

# Installation

```bash
git clone https://github.com/sshpie/shodan-fetch
cd shodan-fetch
pip install -r requirements.txt
playwright install chromium
```

Requires Python 3.11 or later.

# Usage

**One time, log in:**

```console
python shodan-fetch.py --login
```

A browser window opens. Log in to your Shodan account, then press Enter in the terminal. The login persists in a Chrome profile at `~/.config/shodan-fetch/profile` and is reused by every later run. Re-run `--login` if the session ever expires.

**Run queries:**

```console
# single query, auto-paginates all results, rich JSON
python shodan-fetch.py 'http.title:"Ollama"'

# multiple queries from a file (one dork per line, # for comments)
python shodan-fetch.py --file dorks.txt

# cap pages per query (default: all, hard cap 100 pages, ~1000 hosts)
python shodan-fetch.py --max-pages 5 'http.title:"MLflow"'

# flat IP list for piping
python shodan-fetch.py --ips-only 'http.title:"Langfuse"'

# write IPs to file
python shodan-fetch.py --file dorks.txt --output ips.txt
```

**Pipe to other tools:**

```console
# feed JAXEN
python shodan-fetch.py --ips-only 'http.title:"Weaviate"' | jaxen import --no-lookup

# feed aimap
python shodan-fetch.py --ips-only 'http.title:"Ollama"' --output ips.txt && aimap -iL ips.txt
```

# Facet and host modes

Two extra modes ride the same authenticated session, both reading Shodan's server-rendered pages with no API credits.

**`--facet <fields>`** returns population analytics. Full distribution of a query across any Shodan facet field (vuln, http.status, tag, ssl.version, ssl.cert.issuer.cn, pivot hashes, data-layer keys, and about 85 more). All fields fire in one parallel batch, for every query given.

```console
python shodan-fetch.py 'http.title:"Label Studio"' --facet vuln,http.status,tag
```

`http.status` and `vuln` turn a raw hit count into a real one. How many of the population actually return 200 versus 500, and which CVEs they carry, before probing a single host.

**`--host <ips>`** returns a per-IP dossier. Every open port (banner plus crawl timestamp), the web-technology fingerprint, tags, CVEs, the General Information block, plus the `/raw` and `/history` URLs. IPs are fetched in parallel batches.

```console
python shodan-fetch.py --host 51.159.71.107,20.42.106.87
```

`--facet` and `--host` are mutually exclusive and do not take `--output` or `--ips-only` (both emit structured JSON to stdout).

# Output

Default JSON: one object per query, each with the total count, the per-query facets, the full country breakdown, and a `hosts` array of full records:

```json
[
  {
    "query": "http.title:\"Ollama\"",
    "count": "80,157",
    "countries": { "US": 4254, "CN": 3210, "DE": 2751 },
    "facets": {
      "Top Ports": [{ "label": "443", "count": "8,294" }],
      "Top Organizations": [{ "label": "Hetzner Online GmbH", "count": "1,450" }]
    },
    "hosts": [
      {
        "ip": "1.2.3.4", "port": 443,
        "hostnames": ["host.example.com"],
        "org": "Example Inc", "country": "United States", "city": "Dublin",
        "timestamp": "2026-06-01T06:02:31",
        "banner": "HTTP/1.1 200 OK\nServer: nginx\n...",
        "ssl": { "issuer_org": "...", "subject_cn": "...", "tls_versions": "..." },
        "components": ["Nginx"], "tags": ["cloud"]
      }
    ]
  }
]
```

`--ips-only` outputs one IP per line, deduplicated across all queries.

# Dorks file format

```
# vector databases
http.title:"Qdrant"
http.title:"Weaviate"
http.title:"Milvus"

# LLM inference
http.title:"Ollama"
http.title:"Open WebUI"
```

# Notes

- Use `http.title:` and similar server-rendered queries. `product:` filter dorks render in JavaScript and return no results via this method.
- Shodan's web UI shows 10 results per page and caps pagination at 100 pages (about 1000 unique hosts per query, often fewer after cross-port dedup). The reported `count` is the full population; the `hosts` array is what is retrievable through the UI.
- The Chrome profile holds your Shodan auth cookies. Keep `~/.config/shodan-fetch/` out of version control.

# Scope

shodan-fetch reads the Shodan web UI through your own authenticated session. It does not probe targets directly, does not authenticate to discovered services, does not POST data, does not execute exploits. Use the data it returns under whatever scope your engagement allows.

# Our other projects

- [JAXEN](https://github.com/sshpie/JAXEN) — stateful Shodan harvest platform, integrates shodan-fetch natively via `jaxen hunt --web`
- [aimap](https://github.com/sshpie/aimap) — AI/ML infrastructure fingerprint scanner
- [scanner](https://github.com/sshpie/scanner) — active TCP+TLS banner stage between passive discovery and aimap
- [recongraph](https://github.com/sshpie/recongraph) — typed provenance graph for multi-source recon
- [VisorLog](https://github.com/sshpie/visorlog) — finding ledger and ingest pipeline

# License

MIT. Part of the  toolchain. Contact: [sshpie.com](https://sshpie.com)
