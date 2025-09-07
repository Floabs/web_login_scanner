#!/usr/bin/env python3
import asyncio, re, socket, csv, sys, html, unicodedata
from urllib.parse import urlparse
import pandas as pd
import httpx

# --------- Simple keyword list for login hints in raw HTML ---------
LOGIN_KEYWORDS = [
    "log in", "login", "sign in", "signin",
    "anmelden", "einloggen", "konto", "portal", "auth", "zugang", "sso"
]
# also keep the password-input heuristic
PASSWORD_INPUT = re.compile(r"<input[^>]+type=['\"]?password['\"]?", re.I)

SSO_PROVIDERS = {
    "azuread": re.compile(r"login\.microsoft", re.I),
    "okta":    re.compile(r"\.okta\.com", re.I),
    "auth0":   re.compile(r"auth0\.com", re.I),
}

def normalize_html_text(s: str) -> str:
    """Decode HTML entities, normalize unicode, and lowercase."""
    s = html.unescape(s or "")
    s = unicodedata.normalize("NFKC", s)
    return s.lower()

async def dns_ok(h):
    try:
        socket.getaddrinfo(h, None)
        return True
    except Exception:
        return False

async def probe(domain, client, sem):
    async with sem:
        row = {"domain": domain, "resolved": False, "reachable": False,
               "status": None, "final_url": "", "redirect_chain": "",
               "login": False, "sso": "", "error": ""}

        if not await dns_ok(domain):
            row["error"] = "dns_failure"
            return row
        row["resolved"] = True

        for scheme in ("https://", "http://"):
            try:
                r = await client.get(
                    f"{scheme}{domain}",
                    follow_redirects=True,                     # follow redirect chain
                    timeout=httpx.Timeout(5.0)                 # short total timeout
                )
                row["reachable"]   = True
                row["status"]      = r.status_code
                row["final_url"]   = str(r.url)
                row["redirect_chain"] = " > ".join(str(h.url) for h in (r.history + [r]))

                # --- FULL page source (decoded HTML)
                # HTTPX decodes to text using charset from headers, else utf-8. :contentReference[oaicite:1]{index=1}
                html_src = r.text or ""
                html_norm = normalize_html_text(html_src)
                path_norm = normalize_html_text(getattr(r.url, "path", ""))

                # --- Login detection: keywords in source OR path, or password field
                if any(k in html_norm for k in LOGIN_KEYWORDS) or any(k in path_norm for k in LOGIN_KEYWORDS):
                    row["login"] = True
                elif PASSWORD_INPUT.search(html_src):
                    row["login"] = True

                # --- SSO detection (redirects + body)
                blob = normalize_html_text(row["redirect_chain"] + " " + html_src)
                for name, rx in SSO_PROVIDERS.items():
                    if rx.search(blob):
                        row["sso"] = name
                        break

                return row
            except Exception as e:
                row["error"] = f"{type(e).__name__}: {e}"
                continue
        return row

async def main(input_xlsx, output_csv):
    df = pd.read_excel(input_xlsx, header=None)
    domains_raw = df.iloc[:, 0].astype(str).str.strip().tolist()

    # sanitize & dedupe
    seen, domains = set(), []
    for v in domains_raw:
        if not v:
            continue
        host = urlparse(v).netloc if "://" in v else v
        host = host.split("/")[0]
        if host and host not in seen:
            seen.add(host); domains.append(host)

    sem = asyncio.Semaphore(10)
    # Use realistic headers so sites serve the normal markup
    headers = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    async with httpx.AsyncClient(headers=headers, http2=True) as client:
        rows = await asyncio.gather(*(probe(d, client, sem) for d in domains))

    # Write CSV
    fieldnames = ["domain","resolved","reachable","status","final_url","redirect_chain","login","sso","error"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print("Results saved:", output_csv)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.xlsx output.csv")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
