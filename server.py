#!/usr/bin/env python3
"""Cyber threat feed: pulls security news, advisories and vulnerabilities, serves them at http://localhost:8000."""
import html
import json
import re
import webbrowser
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PORT = 8000
CACHE_SECONDS = 600
ITEMS_PER_FEED = 30
HERE = Path(__file__).parent

# (name, category, url[, cyber_only]) -- add any RSS/Atom feed here; cyber_only keeps just cyber-related items
RSS_FEEDS = [
    ("The Hacker News", "news", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "news", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "news", "https://krebsonsecurity.com/feed/"),
    ("WIRED Security", "news", "https://www.wired.com/feed/category/security/latest/rss"),
    ("SecurityWeek", "news", "https://feeds.feedburner.com/securityweek"),
    ("Dark Reading", "news", "https://www.darkreading.com/rss.xml"),
    ("The Record", "news", "https://therecord.media/feed"),
    ("SANS ISC", "news", "https://isc.sans.edu/rssfeed.xml"),
    ("Schneier on Security", "news", "https://www.schneier.com/feed/atom/"),
    ("Security Affairs", "news", "https://securityaffairs.com/feed"),
    ("Help Net Security", "news", "https://www.helpnetsecurity.com/feed/"),
    ("Infosecurity Magazine", "news", "https://www.infosecurity-magazine.com/rss/news/"),
    ("Risky Business News", "news", "https://risky.biz/feeds/risky-business-news/"),
    # Leadership, strategy, regulation
    ("CSO Online", "leadership", "https://www.csoonline.com/feed/"),
    ("Cybersecurity Dive", "leadership", "https://www.cybersecuritydive.com/feeds/news/"),
    ("SecurityWeek CISO Strategy", "leadership", "https://www.securityweek.com/category/ciso-strategy/feed/"),
    ("Cisco Talos", "threat intel", "https://blog.talosintelligence.com/rss/"),
    ("Unit 42", "threat intel", "https://unit42.paloaltonetworks.com/feed/"),
    ("Microsoft Security Blog", "threat intel", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Red Hat Security Blog", "threat intel", "https://www.redhat.com/en/rss/blog/channel/security"),
    ("Google Threat Intelligence (Mandiant)", "threat intel", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("AWS Security Blog", "threat intel", "https://aws.amazon.com/blogs/security/feed/"),
    ("Wiz Research", "threat intel", "https://www.wiz.io/feed/rss.xml"),
    ("Datadog Security Labs", "threat intel", "https://securitylabs.datadoghq.com/rss/feed.xml"),
    # Healthcare
    ("Health-ISAC", "healthcare", "https://health-isac.org/feed/"),
    ("HIPAA Journal", "healthcare", "https://www.hipaajournal.com/feed/"),
    ("DataBreaches.net", "healthcare", "https://databreaches.net/feed/"),
    # National cyber agencies / government CERTs
    ("CISA Advisories (US)", "government", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("CISA News (US)", "government", "https://www.cisa.gov/news.xml"),
    ("FBI IC3 Public Service Announcements (US)", "government", "https://www.ic3.gov/PSA/RSS"),
    ("FBI Press Releases (US)", "government", "https://www.fbi.gov/feeds/national-press-releases/rss.xml", True),
    ("Department of Justice (US)", "government", "https://www.justice.gov/news/rss?type=press_release&m=1", True),
    ("NIST (US)", "government", "https://www.nist.gov/news-events/news/rss.xml", True),
    ("CISA ICS Advisories (US)", "government", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
    ("CERT/CC (US)", "government", "https://www.kb.cert.org/vulfeed"),
    ("NCSC (UK)", "government", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
    ("CERT-EU (EU)", "government", "https://cert.europa.eu/publications/security-advisories-rss"),
    ("CERT-EU Threat Intel (EU)", "government", "https://cert.europa.eu/publications/threat-intelligence-rss"),
    ("Canadian Centre for Cyber Security", "government", "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en"),
    ("JPCERT/CC (Japan)", "government", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"),
    ("JVN (Japan)", "government", "https://jvn.jp/en/rss/jvn.rdf"),
    ("HKCERT (Hong Kong)", "government", "https://www.hkcert.org/getrss/security-bulletin"),
    # Vendor PSIRTs -- CVEs straight from the vendor
    ("Microsoft MSRC", "vendor", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco PSIRT", "vendor", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("Fortinet PSIRT", "vendor", "https://filestore.fortinet.com/fortiguard/rss/ir.xml"),
    ("Palo Alto Networks", "vendor", "https://security.paloaltonetworks.com/rss.xml"),
    ("Oracle", "vendor", "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"),
    ("Ivanti", "vendor", "https://www.ivanti.com/blog/topics/security-advisory/rss"),
    ("Siemens ProductCERT", "vendor", "https://cert-portal.siemens.com/productcert/rss/advisories.atom"),
    ("AWS Security Bulletins", "vendor", "https://aws.amazon.com/security/security-bulletins/rss/feed/"),
    ("Google Cloud Security Bulletins", "vendor", "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml"),
    ("Ubuntu Security Notices", "vendor", "https://ubuntu.com/security/notices/rss.xml"),
    ("Debian Security Advisories", "vendor", "https://www.debian.org/security/dsa"),
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CYBER_RE = re.compile(r"\b(cyber|cyberattacks?|cybercrim\w*|cybersecurity|hack\w*|ransomware|malware|botnet|"
                      r"data breach\w*|intrusions?|phishing|computer fraud|spyware|ddos|information-stealing|"
                      r"cryptograph\w*|post-quantum|zero trust|vulnerabilit\w*)\b", re.I)
kev_ids = set()


def fetch(url):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (cyber-feed)", "Accept": "*/*"})
    with urlopen(req, timeout=30) as r:
        return r.read()


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat()


def clean(text, limit=300):
    text = re.sub(r"<[^>]+>", " ", html.unescape(text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def item(source, category, title, link, date, summary, severity="", cves=None, packages=""):
    return {
        "source": source, "category": category, "title": title, "link": link, "date": date,
        "summary": summary, "severity": severity, "packages": packages,
        "cves": sorted({c.upper() for c in (cves if cves is not None else CVE_RE.findall(f"{title} {summary}"))}),
    }


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child_text(el, *names):
    for c in el:
        if local(c.tag) in names and (c.text or "").strip():
            return c.text
    return ""


def parse_feed(name, category, url, cyber_only=False):
    root = ET.fromstring(fetch(url))
    items = []
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"):
            continue
        link = child_text(el, "link")
        if not link:  # Atom: <link href="..."/>
            link = next((c.get("href", "") for c in el
                         if local(c.tag) == "link" and c.get("rel", "alternate") == "alternate"), "")
        items.append(item(
            name, category, clean(child_text(el, "title"), 200), link.strip(),
            parse_date(child_text(el, "pubDate", "published", "updated", "date")),
            clean(child_text(el, "description", "summary", "content")),
        ))
    if cyber_only:
        items = [i for i in items if CYBER_RE.search(f'{i["title"]} {i["summary"]}')]
    return items[:ITEMS_PER_FEED]


def parse_kev():
    data = json.loads(fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    vulns = data["vulnerabilities"]
    kev_ids.clear()
    kev_ids.update(v["cveID"] for v in vulns)
    vulns = sorted(vulns, key=lambda v: v["dateAdded"], reverse=True)[:50]
    return [item(
        "CISA KEV", "vulnerability",
        f'{v["cveID"]}: {v["vendorProject"]} {v["product"]} — {v["vulnerabilityName"]}',
        f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}', parse_date(v["dateAdded"]),
        clean(f'{v["shortDescription"]} Action: {v["requiredAction"]} Due: {v["dueDate"]}.'
              + (" Used in ransomware campaigns." if v.get("knownRansomwareCampaignUse") == "Known" else ""), 400),
        "EXPLOITED", [v["cveID"]],
    ) for v in vulns]


def parse_github():
    data = json.loads(fetch("https://api.github.com/advisories?type=reviewed&per_page=50&sort=published&direction=desc"))
    out = []
    for a in data:
        pkgs = ", ".join(f'{v["package"]["ecosystem"]}/{v["package"]["name"]}'
                         for v in a.get("vulnerabilities") or [] if v.get("package"))
        out.append(item(
            "GitHub Advisories", "vulnerability", f'{a.get("cve_id") or a["ghsa_id"]}: {a["summary"]}',
            a["html_url"], parse_date(a.get("published_at")), clean(a.get("description")),
            (a.get("severity") or "").upper(), [a["cve_id"]] if a.get("cve_id") else [], pkgs,
        ))
    return out


def parse_nvd():
    end = datetime.now(timezone.utc)
    q = urlencode({
        "pubStartDate": (end - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "cvssV3Severity": "CRITICAL", "resultsPerPage": 100,
    })
    data = json.loads(fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}"))
    out = []
    for v in data.get("vulnerabilities", []):
        c = v["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score = next((m[0]["cvssData"]["baseScore"] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")
                      if (m := c.get("metrics", {}).get(k))), "?")
        out.append(item(
            "NVD (critical, 7d)", "vulnerability", f'{c["id"]} (CVSS {score})',
            f'https://nvd.nist.gov/vuln/detail/{c["id"]}', parse_date(c.get("published")),
            clean(desc), "CRITICAL", [c["id"]],
        ))
    return out


def parse_ransomware():
    data = json.loads(fetch("https://api.ransomware.live/v2/recentvictims"))
    return [item(
        "ransomware.live", "ransomware", f'{v.get("group") or "Unknown group"} claims {v.get("victim") or "unknown victim"}',
        v.get("url") or "", parse_date(v.get("attackdate") or v.get("discovered")),
        f'Sector: {v.get("activity") or "unknown"} · Country: {v.get("country") or "unknown"}', cves=[],
    ) for v in data]


SOURCES = [(f[0], lambda f=f: parse_feed(*f)) for f in RSS_FEEDS] + [
    ("CISA KEV", parse_kev), ("GitHub Advisories", parse_github), ("NVD", parse_nvd),
    ("ransomware.live", parse_ransomware),
]
_cache = {"time": None, "data": None}


def collect():
    items, errors = [], []

    def run(source):
        name, fn = source
        try:
            return fn(), None
        except Exception as e:  # one broken feed shouldn't break the page
            return [], f"{name}: {e}"

    with ThreadPoolExecutor(max_workers=8) as pool:
        for got, err in pool.map(run, SOURCES):
            items += got
            if err:
                errors.append(err)
    items.sort(key=lambda i: i["date"] or "", reverse=True)
    return {"updated": datetime.now(timezone.utc).isoformat(), "items": items,
            "exploited": sorted(kev_ids), "errors": errors}


def get_data(force=False):
    now = datetime.now(timezone.utc)
    if force or not _cache["time"] or (now - _cache["time"]).total_seconds() > CACHE_SECONDS:
        _cache["data"], _cache["time"] = collect(), now
    return _cache["data"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith(("/api/feed", "/feed.json")):
            self.send(json.dumps(get_data("refresh=1" in self.path)).encode(), "application/json")
        elif self.path in ("/", "/index.html"):
            self.send((HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"Cyber feed running at http://localhost:{PORT}  (Ctrl+C to stop)")
    webbrowser.open(f"http://localhost:{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
