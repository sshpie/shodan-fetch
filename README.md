# shodan-fetch

Authenticated Shodan scraper that uses a browser session instead of API tokens. Run parallel queries against Shodan's web UI with no credits consumed.

## How it works

Logs into Shodan once via a headed browser and saves the session to disk. Subsequent runs load the saved session, fire all queries in parallel via `fetch()` inside the browser context, and extract hit counts and IPs from the HTML. No API key required.

**Speed:** ~1.2 seconds for any batch of queries regardless of count, using `Promise.all` across tabs with resource blocking (images/CSS/fonts stripped).

## Install

```bash
pip install playwright
playwright install chromium
```

## Usage

**First run — save your session:**
```bash
python shodan-fetch.py --login
```
A browser window opens. Log in to your Shodan account, then press Enter in the terminal. Session saves to `~/.config/shodan-fetch/session.json`.

**Run queries:**
```bash
# single query — outputs JSON with count + IPs
python shodan-fetch.py 'http.title:"Ollama"'

# multiple queries from a file (one dork per line, # = comment)
python shodan-fetch.py --file dorks.txt

# paginate (10 IPs per page)
python shodan-fetch.py --pages 5 'http.title:"MLflow"'

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

## Output format

Default JSON output:
```json
[
  {
    "query": "http.title:\"Ollama\"",
    "count": "80,157",
    "ips": ["1.2.3.4", "5.6.7.8", "..."]
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

## Session management

Sessions expire periodically. Re-run `--login` when queries return empty results.

Override the script path via `SHODAN_FETCH` env var:
```bash
export SHODAN_FETCH=/path/to/shodan-fetch.py
```

## Notes

- Only works with `http.title:` and similar SSR-rendered Shodan queries. `product:` filter dorks are JS-rendered and return no results via this method.
- Shodan's web UI shows 10 results per page. Use `--pages N` to collect more IPs per query.
- The session file contains your Shodan auth cookies. Keep it out of version control.

## Integration with JAXEN

[JAXEN](https://github.com/nuclide-research/JAXEN) integrates shodan-fetch natively via `jaxen hunt --web`. Auto-falls back to web mode when no API key is configured.
