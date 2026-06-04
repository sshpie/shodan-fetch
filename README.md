# shodan-fetch

Authenticated Shodan scraper that harvests the web UI through a persistent logged-in browser, returning per-host records and facet distributions without spending API query credits.

It runs a real Chrome profile with a durable session cookie, then calls `fetch()` from inside that page context so every query rides the session automatically. Shodan renders all result cards, facet sidebars, and country breakdowns server-side, so one HTML response per page is the full dataset. Images, fonts, and the map widget are blocked context-wide, so each round-trip is fast. All queries and all pages of each query fire in parallel via `Promise.all`. Three modes share the same authenticated session: a default search mode that auto-paginates and returns structured host records, a facet mode that returns full field distributions across any of Shodan's ~91 facet fields, and a host mode that returns a full per-IP dossier.

## Install

```bash
pip install playwright
playwright install chromium
```

Python 3.10+. `playwright` is the only dependency.

## Usage

**Log in once:**

```bash
python3 shodan-fetch.py --login
```

A browser window opens. Log in to your Shodan account, then press Enter in the terminal. The session persists in a Chrome profile at `~/.config/shodan-fetch/profile` and is reused on every later run. Re-run `--login` if the session expires; the tool fails loud and never returns a silent empty result.

**Search mode (default):**

```bash
python3 shodan-fetch.py 'http.title:"MLflow"'               # single dork, auto-paginates
python3 shodan-fetch.py --file dorks.txt                     # batch from file (# = comment)
python3 shodan-fetch.py --file dorks.txt --max-pages 5       # cap pages per query
python3 shodan-fetch.py 'http.title:"Weaviate"' --ips-only   # flat deduplicated IP list
python3 shodan-fetch.py --file dorks.txt --output ips.txt    # write IPs to file
```

**Facet mode:**

```bash
python3 shodan-fetch.py 'http.title:"Label Studio"' --facet vuln,http.status,tag,ssl.version
```

Returns the full distribution of the query across each requested field. All fields fire in one parallel batch, for each query given. `--facet` and `--host` are mutually exclusive; neither takes `--output` or `--ips-only`.

**Host mode:**

```bash
python3 shodan-fetch.py --host 51.159.71.107,20.42.106.87
```

Returns a full per-IP dossier: every open port with banner, web technology fingerprint, CVEs, tags, and the `/raw` and `/history` URLs. IPs are fetched in parallel batches of 20.

### All flags

| Flag | Effect |
|------|--------|
| `--login` | Open browser, log in once; session persists |
| `--file FILE`, `-f FILE` | File with one dork per line (`#` = comment) |
| `--max-pages N` | Cap pages per query (default: 0 = all; hard cap 100 pages) |
| `--batch-size N` | Queries per parallel batch (default: 20) |
| `--ips-only` | Output flat deduplicated IP list, one per line |
| `--output FILE`, `-o FILE` | Write IPs to file (implies `--ips-only`) |
| `--facet FIELDS` | Comma-separated facet fields for population analytics |
| `--host IPS` | Comma-separated IPs for full per-IP dossier |

## Output format

Default search mode emits JSON, one object per query:

```json
[
  {
    "query": "http.title:\"Ollama\"",
    "count": "80,157",
    "countries": {"US": 4254, "CN": 3210, "DE": 2751},
    "facets": {
      "Top Ports": [{"label": "443", "count": "8,294"}],
      "Top Organizations": [{"label": "Hetzner Online GmbH", "count": "1,450"}]
    },
    "hosts": [
      {
        "ip": "192.0.2.1",
        "port": 443,
        "hostnames": ["host.example.com"],
        "org": "Example Inc",
        "country": "United States",
        "city": "Dublin",
        "timestamp": "2026-06-01T06:02:31",
        "banner": "HTTP/1.1 200 OK\nServer: nginx\n...",
        "ssl": {"issuer_org": "...", "subject_cn": "...", "tls_versions": "..."},
        "components": ["Nginx"],
        "tags": ["cloud"]
      }
    ]
  }
]
```

The sidebar facets in `facets` cover: Top Countries, Top Ports, Top Organizations, Top Products, Top Operating Systems. These are always returned for search mode and do not require `--facet`.

Facet mode emits a per-query, per-field structure with `value` and `count` pairs, covering any of Shodan's ~91 fields including `vuln`, `http.status`, `tag`, `ssl.version`, `ssl.cert.issuer.cn`, and the pivot hashes.

Host mode emits per-IP objects with `ip`, `tags`, `webtech`, `vulns`, `general` (general information block), `services` (port, transport, heading), `banners`, `raw_url`, and `history_url`.

`--ips-only` emits one IP per line, deduplicated across all queries.

## Example

```
$ python3 shodan-fetch.py 'http.title:"Ollama"' --max-pages 1 --ips-only
[*]   80,157  (1 pages)  http.title:"Ollama"
192.0.2.10
192.0.2.11
198.51.100.4
```

Shodan caps pagination at 100 pages (~1,000 unique hosts per query, often fewer after cross-port dedup). The reported `count` is the full population; the `hosts` array is what is retrievable through the web UI.

## Pipe to other tools

```bash
# feed jaxen
python3 shodan-fetch.py --ips-only 'http.title:"Weaviate"' | jaxen import --no-lookup

# feed aimap
python3 shodan-fetch.py --ips-only 'http.title:"Ollama"' --output ips.txt && aimap -iL ips.txt
```

## Notes

- `http.title:` and similar SSR-rendered filters work. `product:` dorks are JS-rendered and return no results via this method.
- The Chrome profile holds your Shodan auth cookies. Keep `~/.config/shodan-fetch/` out of version control.
- Upgrading from an older version that used `session.json`? It is imported into the persistent profile automatically on first run.

## What shodan-fetch is not

shodan-fetch is not a Shodan API client. It does not call `api.shodan.io`. It does not use API query credits. It reads the same server-rendered HTML a logged-in browser would read, using the session cookie to authenticate. Results are bounded by the web UI pagination cap, not the API.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
