"""Where jobs come from, and tidying what job alerts say about them. Local rules only.

- Source taxonomy: (type, name) for the email a job arrived in. Types:
  job_board, company_careers, startup_platform, community, ats_feed, other.
- Company display names: real names for career-site relays (Amex Careers -> American
  Express, EYJobAlerts -> EY, standardch -> Standard Chartered), acronyms kept uppercase.
- Titles: trailing location suffixes ("... - Kolkata, WB, IN, 700091",
  "... - INDIA - PUNE - BIRLASOFT OFFICE ...") are moved into the location field.
"""

from __future__ import annotations

import re

from mailwarden.core.recruiting import company_from_local_part, domain_matches, registrable_domain
from mailwarden.core.text import clean

SOURCE_TYPES = ("job_board", "company_careers", "startup_platform", "community", "ats_feed", "other")
SOURCE_TYPE_LABELS = {
    "job_board": "Job boards", "company_careers": "Company careers", "startup_platform": "Startup platforms",
    "community": "Communities", "ats_feed": "Company alerts (ATS)", "other": "Other",
}

# domain -> (type, name)
_KNOWN: dict[str, tuple[str, str]] = {
    "linkedin.com": ("job_board", "LinkedIn"), "naukri.com": ("job_board", "Naukri"),
    "indeed.com": ("job_board", "Indeed"), "foundit.in": ("job_board", "foundit"),
    "monsterindia.com": ("job_board", "foundit"), "internshala.com": ("job_board", "Internshala"),
    "glassdoor.com": ("job_board", "Glassdoor"), "glassdoor.co.in": ("job_board", "Glassdoor"),
    "shine.com": ("job_board", "Shine"), "apna.co": ("job_board", "apna"), "hirist.tech": ("job_board", "hirist"),
    "hirist.com": ("job_board", "hirist"), "iimjobs.com": ("job_board", "iimjobs"),
    "timesjobs.com": ("job_board", "TimesJobs"),
    "cutshort.io": ("startup_platform", "Cutshort"), "wellfound.com": ("startup_platform", "Wellfound"),
    "angel.co": ("startup_platform", "Wellfound"), "instahyre.com": ("startup_platform", "Instahyre"),
    "workatastartup.com": ("startup_platform", "Work at a Startup"), "hirect.in": ("startup_platform", "Hirect"),
    "unstop.com": ("community", "Unstop"), "devfolio.co": ("community", "Devfolio"),
    "hackerearth.com": ("community", "HackerEarth"), "geeksforgeeks.org": ("community", "GeeksforGeeks"),
    "topmate.io": ("community", "Topmate"),
}
_ATS = {
    "jobs2web.com": "jobs2web", "successfactors.com": "SuccessFactors", "successfactors.eu": "SuccessFactors",
    "smartrecruiters.com": "SmartRecruiters", "myworkday.com": "Workday", "myworkdayjobs.com": "Workday",
    "greenhouse.io": "Greenhouse", "greenhouse-mail.io": "Greenhouse", "lever.co": "Lever",
    "ashbyhq.com": "Ashby", "icims.com": "iCIMS", "taleo.net": "Taleo", "avature.net": "Avature",
    "oraclecloud.com": "Oracle Recruiting",
}
_FREEMAIL = frozenset({"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.co.in", "icloud.com"})

# Company display names: alias (company_key form) -> display.
_COMPANY_ALIASES = {
    "amex": "American Express", "american express": "American Express", "americanexpress": "American Express",
    "standardch": "Standard Chartered", "standardchartered": "Standard Chartered", "sc": "Standard Chartered",
    "anzbanking": "ANZ", "anz": "ANZ", "birlasoftl": "Birlasoft", "birlasoft": "Birlasoft",
    "capgemitecp": "Capgemini", "capgemini": "Capgemini", "hcltech": "HCLTech", "hcl tech": "HCLTech",
    "hcl technologies": "HCLTech", "jpmc": "JPMorgan Chase", "jpmorgan": "JPMorgan Chase", "gs": "Goldman Sachs",
    "goldman": "Goldman Sachs", "exlservice": "EXL", "ey": "EY", "eyjobalerts": "EY", "wsp": "WSP",
    "kochind": "Koch Industries", "koch": "Koch Industries",
}
ACRONYMS = frozenset({
    "EY", "KPMG", "HCL", "TCS", "IBM", "SAP", "HSBC", "ANZ", "ADP", "EXL", "AMD", "GE", "BNY", "UBS", "BCG", "DBS",
    "ICICI", "HDFC", "SBI", "NTT", "LTI", "DXC", "EPAM", "CGI", "ZS", "PTC", "NVIDIA", "ABB", "BP", "HP", "HPE",
    "AT&T", "WSP", "ADNOC", "PWC",
})
_ACRONYM_DISPLAY = {"PWC": "PwC", "NVIDIA": "NVIDIA"}


_RECRUITING_SUFFIX = re.compile(
    r"(?:\s+(?:early\s+)?(?:careers?|recruiting|recruitment|talent(?:\s+acquisition)?(?:\s+team)?|hiring(?:\s+team)?|"
    r"jobs?|job\s+alerts?|campus|university\s+relations|people\s+team))+\s*$",
    re.IGNORECASE,
)


def display_company(name: str | None) -> str | None:
    """Real, consistently cased company name: recruiting words dropped, aliases, uppercase acronyms."""
    if not name:
        return None
    text = re.sub(r"\s+", " ", clean(name)).strip(" -|·,")
    text = _RECRUITING_SUFFIX.sub("", text).strip(" -|·,") or text
    if not text:
        return None
    key = re.sub(r"[^a-z0-9& ]+", "", text.lower()).strip()
    if key in _COMPANY_ALIASES:
        return _COMPANY_ALIASES[key]
    if text.islower():
        text = " ".join(w.capitalize() for w in text.split(" "))
    words = []
    for word in text.split(" "):
        bare = re.sub(r"[^A-Za-z&]", "", word)
        if bare.upper() in ACRONYMS and len(bare) >= 2:
            words.append(word.replace(bare, _ACRONYM_DISPLAY.get(bare.upper(), bare.upper())))
        else:
            words.append(word)
    return " ".join(words)[:200]


def company_for_relay(display_name: str, address: str) -> str | None:
    """A career-site relay's real company: from the display name ('Amex Careers') or local part."""
    from mailwarden.core.recruiting import company_from_sender

    domain = address.rpartition("@")[2].lower()
    name = company_from_sender(display_name, domain, address) or company_from_local_part(address)
    return display_company(name)


def classify_source(sender_address: str | None, sender_label: str | None) -> tuple[str, str]:
    """(type, name) for the email a job alert came from."""
    address = (sender_address or "").lower()
    domain = address.rpartition("@")[2]
    label = clean(sender_label or "")
    for dom, (kind, name) in _KNOWN.items():
        if domain and domain_matches(domain, frozenset({dom})):
            if name == "Naukri" and re.search(r"\bcampus\b", label, re.IGNORECASE):
                return kind, "Naukri Campus"
            return kind, name
    for dom, ats in _ATS.items():
        if domain and domain_matches(domain, frozenset({dom})):
            company = company_for_relay(label, address) if address else display_company(label)
            if not company or company.lower() == ats.lower():
                return "ats_feed", ats
            return "ats_feed", f"{company} ({ats})"
    if not domain and label:  # no address (e.g. old rows): recognise well-known senders by name
        low = label.lower()
        for kind, name in sorted(set(_KNOWN.values()), key=lambda kn: -len(kn[1])):
            if re.search(rf"\b{re.escape(name.lower())}\b", low):
                if name == "Naukri" and "campus" in low:
                    return kind, "Naukri Campus"
                return kind, name
    if domain and domain not in _FREEMAIL:
        company = None
        if label and "." not in label and _RECRUITING_SUFFIX.sub("", " " + label).strip(" -|·,"):
            company = display_company(label)  # the name says who it is ("Koch Careers")
        if not company:  # only recruiting words ("Talent Acquisition Team"): use the domain
            company = display_company(registrable_domain(domain).split(".")[0])
        return "company_careers", company or registrable_domain(domain)
    return "other", f"Other ({domain or 'unknown'})"


# --- titles with location suffixes -----------------------------------------------------------

_STATE = r"(?:[A-Z]{2}|Karnataka|Maharashtra|Telangana|Tamil Nadu|Haryana|Delhi|Uttar Pradesh|West Bengal|Kerala)"
_SUFFIX_CITY = re.compile(
    rf"\s+[-–|]\s+([A-Za-z][A-Za-z .'()]+?)(?:,\s*{_STATE})?,\s*(?:IN|IND|India)(?:,\s*\d{{6}})?\s*$"
)
_SUFFIX_INDIA = re.compile(r"\s+[-–]\s+INDIA\s+[-–]\s+([A-Z][A-Z .]+?)(?:\s+[-–]\s+.*)?$")
_TRAILING_CITY_WORDS = r"(?:Bengaluru|Bangalore|Gurugram|Gurgaon|Noida|Delhi|New Delhi|Pune|Mumbai|Hyderabad|Chennai|" \
                       r"Kolkata|Kochi|Trivandrum|Ahmedabad|Jaipur|Coimbatore|Mysore|Chandigarh)"
_TRAILING_CITY = re.compile(rf"\s+[-–|]\s+{_TRAILING_CITY_WORDS}\s*$", re.IGNORECASE)


def split_title_location(title: str, location: str | None) -> tuple[str, str | None]:
    """Move a trailing location out of a job title (only fills an empty location)."""
    title = clean(title).strip()
    found = None
    if m := _SUFFIX_INDIA.search(title):
        found = m.group(1).strip().title()
        title = title[: m.start()].rstrip(" -–|")
    elif m := _SUFFIX_CITY.search(title):
        found = m.group(1).strip()
        title = title[: m.start()].rstrip(" -–|")
    while m := _TRAILING_CITY.search(title):  # "... - Gurgaon" left before "- Gurugram, HR, IN"
        found = found or m.group(0).strip(" -–|")
        title = title[: m.start()].rstrip(" -–|")
    return title or clean(location or ""), (location or found)


# --- location for de-duplication ---------------------------------------------------------------

_CITY_CANON = {
    "bangalore": "bengaluru", "blr": "bengaluru", "gurgaon": "gurugram", "new delhi": "delhi", "bombay": "mumbai",
    "navi mumbai": "mumbai", "madras": "chennai", "greater noida": "noida", "wfh": "remote",
    "work from home": "remote",
}
_CITIES = ("bengaluru", "gurugram", "noida", "delhi", "pune", "mumbai", "hyderabad", "chennai", "kolkata", "kochi",
           "trivandrum", "ahmedabad", "jaipur", "coimbatore", "mysore", "chandigarh", "remote")


def location_key(location: str | None) -> str:
    """'Bangalore, Karnataka, India' and 'Bengaluru' -> 'bengaluru'; '' when unknown."""
    if not location:
        return ""
    text = " " + re.sub(r"[^a-z ]+", " ", clean(location).lower()) + " "
    for alias, canon in _CITY_CANON.items():
        text = text.replace(f" {alias} ", f" {canon} ")
    for city in _CITIES:
        if f" {city} " in text:
            return city
    words = [w for w in text.split() if w not in ("india", "in", "karnataka", "haryana", "maharashtra", "hybrid")]
    return " ".join(words[:3])
