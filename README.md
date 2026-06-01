# shodan-fetch

Authenticated Shodan scraper that harvests the web UI through a real logged-in browser session instead of the API. Returns the same per-host data and facets the API would, without spending API query credits or a token.

## How it works

The method, in four parts:

1. **One authenticated browser.** A persistent Chrome profile holds a real logged-in Shodan session (cookies), reused across every run. Not a token, not a frozen snapshot — a durable browser login, the way a human stays signed in. `--login` opens it once; it persists.
2. **Assets stripped.** The harvest uses `fetch()`, which pulls only the search HTML. Images / CSS / fonts / the map widget are never requested, so each query is a single small round-trip instead of a 5-10s full page load.
3. **Everything in parallel.** All queries — and all pages of each query — fire at once via `Promise.all` inside the page context, where the session cookie rides automatically (`credentials: 'include'`).
4. **Parse the SSR HTML.** Shodan renders every result card, facet, and the country breakdown server-side, so the one HTML response *is* the data. There is no hidden API (verified at the DevTools network layer: zero XHR/fetch to shodan.io on a live search).

Net effect: a batch of queries returns full host records in ~1-1.5s, authenticated by the session cookie alone.

## Install

```bash
pip install playwright
playwright install chromium
```

## Usage

**Once — log in:**
```bash
python shodan-fetch.py --login
```
A browser window opens. Log in to your Shodan account, then press Enter in the terminal. The login persists in a Chrome profile at `~/.config/shodan-fetch/profile` and is reused by every later run. Re-run `--login` if the session ever expires (the tool tells you when it does — it fails loud, never returns a silent empty result).

**Run queries:**
```bash
# single query — auto-paginates all results, outputs rich JSON
python shodan-fetch.py 'http.title:"Ollama"'

# multiple queries from a file (one dork per line, # = comment)
python shodan-fetch.py --file dorks.txt

# cap pages per query (default: all, hard cap 100 pages = ~1000 hosts)
python shodan-fetch.py --max-pages 5 'http.title:"MLflow"'

# flat IP list for piping
python shodan-fetch.py --ips-only 'http.title:"Langfuse"'

# write IPs to file
python shodan-fetch.py --file dorks.txt --output ips.txt
```

**Pipe to other tools:**
```bash
# feed jaxen (JAXEN recon platform)
python shodan-fetch.py --ips-only 'http.title:"Weaviate"' | jaxen import --no-lookup

# feed aimap
python shodan-fetch.py --ips-only 'http.title:"Ollama"' --output ips.txt && aimap -iL ips.txt
```

## Facet analysis & host dossiers

Two more modes ride the same authenticated session, both reading Shodan's
server-rendered pages with no API credits:

**`--facet <fields>`** — population analytics. Returns the full distribution of a
query across any Shodan facet field (`vuln`, `http.status`, `tag`, `ssl.version`,
`ssl.cert.issuer.cn`, the pivot hashes, data-layer keys, and ~85 more). All
fields fire in one parallel batch, for every query given.
```bash
# CVE, HTTP-status and tag distribution across the whole population
python shodan-fetch.py 'http.title:"Label Studio"' --facet vuln,http.status,tag
```
`http.status` and `vuln` turn a raw hit count into a real one: how many of the
population actually return 200 vs 500, and which CVEs they carry, before probing
a single host.

**`--host <ips>`** — full per-IP dossier. Every open port (banner + crawl
timestamp), the web-technology fingerprint, tags, CVEs, the General Information
block, plus the `/raw` and `/history` URLs. IPs are fetched in parallel batches.
```bash
python shodan-fetch.py --host 51.159.71.107,20.42.106.87
```

`--facet` and `--host` are mutually exclusive and do not take `--output` /
`--ips-only` (both emit structured JSON to stdout).

## Output format

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

## Dorks file format

```
# vector databases
http.title:"Qdrant"
http.title:"Weaviate"
http.title:"Milvus"

# LLM inference
http.title:"Ollama"
http.title:"Open WebUI"
```

## Notes

- Use `http.title:` and similar SSR-rendered queries. `product:` filter dorks are JS-rendered and return no results via this method.
- Shodan's web UI shows 10 results per page and caps pagination at 100 pages (~1000 unique hosts per query, often fewer after cross-port dedup). The reported `count` is the full population; the `hosts` array is what is retrievable through the UI.
- The Chrome profile holds your Shodan auth cookies. Keep `~/.config/shodan-fetch/` out of version control.
- Upgrading from an older version that used `session.json`? It is imported into the new persistent profile automatically on first run.

## Integration with JAXEN

[JAXEN](https://github.com/nuclide-research/JAXEN) integrates shodan-fetch natively via `jaxen hunt --web`.
