"""`mailwarden profile build`: a job-matching profile from local files only.

Inputs (in the private mailwarden home, never in the repo):
    profile/cv.pdf              your CV (any *.pdf in profile/; the newest is used)
    profile/projects/*.md       one file per project you want used as evidence

Output: profile.yaml (mode 600) with skills weighted by prominence, experience,
seniority, target/avoid roles, locations and projects.

Everything runs locally (no LLM, no network). profile.yaml is later given to the
LLM for fit scoring, so it must never contain contact details: only skill names
from a fixed vocabulary, numbers, your role/location preferences, and project
one-liners scrubbed of emails, phone numbers, links and your name.

Only the project files count as project evidence: the CV's own Projects section is
ignored for both skills and projects.
"""

from __future__ import annotations

import datetime as dt
import difflib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from mailwarden.core.text import clean
from mailwarden.security.fs import check_private, ensure_private_dir, write_private

PROFILE_DIR = "profile"
PROJECTS_DIR = "projects"
PROFILE_FILE = "profile.yaml"
MAX_PDF_PAGES = 10
MAX_TEXT = 200_000

# Sections you own: kept as-is when the profile is refreshed.
PREFERENCE_KEYS = ("seniority", "target_roles", "avoid_roles", "locations", "remote_ok")
HAND_KEYS = ("skill_overrides", "extra_project_skills", "education", "experience_summary", "highlights")
PRESERVED_KEYS = PREFERENCE_KEYS + HAND_KEYS
# Output order of profile.yaml.
KEY_ORDER = ("skills", "skill_overrides", "experience_years", "seniority", "education", "experience_summary",
             "highlights", "target_roles", "avoid_roles", "locations", "remote_ok", "projects",
             "extra_project_skills")
DEFAULT_TARGET_ROLES = ["software engineer", "backend", "full stack", "sde", "sre", "platform engineer"]
DEFAULT_AVOID_ROLES = ["security-only", "sales", "support", "non-engineering"]

# --- skills vocabulary: canonical name -> patterns (case-insensitive unless noted) ------

_SKILLS: dict[str, tuple[str, ...]] = {
    # languages
    "python": (r"\bpython\b",), "java": (r"\bjava\b(?!\s*script)",), "c++": (r"\bc\+\+", r"\bcpp\b"),
    "c": (r"(?-i:\bC\b)(?![+#/])", r"\bc/c\+\+"), "go": (r"\bgolang\b", r"(?-i:\bGo\b)"),
    "javascript": (r"\bjavascript\b", r"(?-i:\bJS\b)"), "typescript": (r"\btypescript\b", r"(?-i:\bTS\b)"),
    "rust": (r"\brust\b",), "kotlin": (r"\bkotlin\b",), "swift": (r"\bswift\b",), "sql": (r"\bsql\b",),
    "bash": (r"\bbash\b", r"\bshell\s+script",), "scala": (r"\bscala\b",), "ruby": (r"\bruby\b",),
    "php": (r"\bphp\b",), "c#": (r"\bc#", r"\.net\b"),
    # backend
    "node.js": (r"\bnode(?:\.?js)?\b",), "express": (r"\bexpress(?:\.js)?\b",), "django": (r"\bdjango\b",),
    "flask": (r"\bflask\b",), "fastapi": (r"\bfastapi\b",), "spring boot": (r"\bspring\s*boot\b", r"\bspring\b"),
    "rest apis": (r"\brest(?:ful)?\s*apis?\b", r"\brestful\b"), "graphql": (r"\bgraphql\b",),
    "grpc": (r"\bgrpc\b",), "microservices": (r"\bmicro-?services?\b",), "websockets": (r"\bweb\s?sockets?\b",),
    # frontend
    "react": (r"\breact(?:\.js|js)?\b(?!\s+native)",), "next.js": (r"\bnext\.?js\b",), "vue": (r"\bvue(?:\.js)?\b",),
    "angular": (r"\bangular\b",), "html": (r"\bhtml5?\b",), "css": (r"\bcss3?\b",),
    "tailwind": (r"\btailwind\b",), "redux": (r"\bredux\b",),
    # data
    "postgresql": (r"\bpostgres(?:ql)?\b",), "mysql": (r"\bmysql\b",), "mongodb": (r"\bmongo(?:db)?\b",),
    "redis": (r"\bredis\b",), "sqlite": (r"\bsqlite\b",), "elasticsearch": (r"\belastic\s?search\b",),
    "kafka": (r"\bkafka\b",), "rabbitmq": (r"\brabbitmq\b",), "spark": (r"\b(?:apache\s+)?spark\b",),
    "pandas": (r"\bpandas\b",), "numpy": (r"\bnumpy\b",), "firebase": (r"\bfirebase\b",),
    # cloud / devops
    "aws": (r"\baws\b", r"\bamazon\s+web\s+services\b"), "gcp": (r"\bgcp\b", r"\bgoogle\s+cloud\b"),
    "azure": (r"\bazure\b",), "docker": (r"\bdocker\b",), "kubernetes": (r"\bkubernetes\b", r"\bk8s\b"),
    "terraform": (r"\bterraform\b",), "ci/cd": (r"\bci\s*/\s*cd\b",), "github actions": (r"\bgithub\s+actions\b",),
    "jenkins": (r"\bjenkins\b",), "linux": (r"\blinux\b", r"\bunix\b"), "nginx": (r"\bnginx\b",),
    "prometheus": (r"\bprometheus\b",), "grafana": (r"\bgrafana\b",), "git": (r"\bgit\b(?!hub)",),
    # ML / AI
    "machine learning": (r"\bmachine\s+learning\b", r"(?-i:\bML\b)"), "deep learning": (r"\bdeep\s+learning\b",),
    "pytorch": (r"\bpytorch\b",), "tensorflow": (r"\btensorflow\b",), "scikit-learn": (r"\bscikit-?learn\b", r"\bsklearn\b"),
    "nlp": (r"\bnlp\b", r"\bnatural\s+language\s+processing\b"), "computer vision": (r"\bcomputer\s+vision\b",),
    "opencv": (r"\bopencv\b",), "llms": (r"\bllms?\b", r"\blarge\s+language\s+models?\b"),
    "langchain": (r"\blangchain\b",), "rag": (r"(?-i:\bRAG\b)", r"\bretrieval[-\s]augmented\b"),
    # CS fundamentals
    "data structures & algorithms": (r"\bdata\s+structures\b", r"\bdsa\b", r"\balgorithms\b"),
    "system design": (r"\bsystem\s+design\b",), "distributed systems": (r"\bdistributed\s+systems?\b",),
    "operating systems": (r"\boperating\s+systems?\b",), "dbms": (r"\bdbms\b", r"\bdatabase\s+management\b"),
    "computer networks": (r"\bcomputer\s+networks?\b", r"\bnetworking\b"), "oop": (r"\boop\b", r"\bobject[-\s]oriented\b"),
    # mobile
    "android": (r"\bandroid\b",), "ios": (r"(?-i:\biOS\b)",), "flutter": (r"\bflutter\b",),
    "react native": (r"\breact\s+native\b",),
}
_SKILL_RE = {name: [re.compile(p, re.IGNORECASE) for p in pats] for name, pats in _SKILLS.items()}

# Prominence weights: where a skill shows up.
_WEIGHTS = {"skills": 1.0, "experience": 2.0, "other": 0.5, "project_file": 3.0}

_HEADINGS = {
    "education": r"education|academic\s+(?:details|qualifications?)",
    "experience": r"(?:work\s+|professional\s+)?experience|internships?|employment",
    "projects": r"(?:personal\s+|academic\s+|key\s+)?projects",
    "skills": r"(?:technical\s+)?skills(?:\s+(?:&|and)\s+\w+)?|technical\s+(?:expertise|proficiency)|technologies",
    "achievements": r"achievements|awards|honou?rs|accomplishments",
    "responsibility": r"positions?\s+of\s+responsibility|leadership|extra[-\s]?curricular.*",
    "other": r"certifications?|publications?|coursework|relevant\s+courses|interests|hobbies",
}
_HEADING_RE = re.compile(
    r"^\s*(?:" + "|".join(f"(?P<{k}>{v})" for k, v in _HEADINGS.items()) + r")\s*:?\s*$", re.IGNORECASE
)

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}
_MON = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
_RANGE = re.compile(
    rf"(?:{_MON}\s*[''’]?\s*(\d{{4}}|\d{{2}})|(\d{{1,2}})\s*/\s*(\d{{4}}))\s*[-–—to]+\s*"
    rf"(?:{_MON}\s*[''’]?\s*(\d{{4}}|\d{{2}})|(\d{{1,2}})\s*/\s*(\d{{4}})|(present|current|now|ongoing|till\s+date))",
    re.IGNORECASE,
)

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b[\w-]+\.(?:com|in|io|dev|app|me|org|net|ai)(?:/\S*)?\b")
_HANDLE = re.compile(r"(?i)\b(?:github|linkedin|leetcode|codeforces|twitter|x)\s*[:/]\s*\S+")


class ProfileError(RuntimeError):
    pass


# --- reading -------------------------------------------------------------------------------

def read_pdf_text(path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    parts = []
    for page in reader.pages[:MAX_PDF_PAGES]:
        parts.append(page.extract_text() or "")
    return clean("\n".join(parts))[:MAX_TEXT]


def split_sections(text: str) -> dict[str, str]:
    """CV text -> {section: text}. Text before the first known heading is 'header'."""
    sections: dict[str, list[str]] = {"header": []}
    current = "header"
    for line in text.splitlines():
        m = _HEADING_RE.match(line) if len(line) <= 60 else None
        if m:
            current = next(k for k, v in m.groupdict().items() if v)
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def find_skills(text: str) -> dict[str, int]:
    counts = {}
    for name, patterns in _SKILL_RE.items():
        n = sum(len(p.findall(text)) for p in patterns)
        if n:
            counts[name] = n
    return counts


# --- derived fields ------------------------------------------------------------------------

def _year(raw: str) -> int:
    y = int(raw)
    return y + 2000 if y < 100 else y


def _month_index(month: str | None, num: str | None) -> int | None:
    if month:
        return _MONTHS[month.lower()[:3]]
    if num and 1 <= int(num) <= 12:
        return int(num)
    return None


def experience_years(experience_text: str, today: dt.date) -> float:
    """Total months covered by date ranges in the Experience section (overlaps counted once)."""
    months: set[int] = set()
    for m in _RANGE.finditer(experience_text):
        m1, y1, n1, y1b, m2, y2, n2, y2b, present = m.groups()
        start_m, start_y = _month_index(m1, n1), (y1 or y1b)
        if start_m is None or not start_y:
            continue
        start = _year(start_y) * 12 + start_m - 1
        if present:
            end = today.year * 12 + today.month - 1
        else:
            end_m, end_y = _month_index(m2, n2), (y2 or y2b)
            if end_m is None or not end_y:
                continue
            end = _year(end_y) * 12 + end_m - 1
        if 0 <= end - start <= 12 * 40:
            months.update(range(start, end + 1))
    return round(len(months) / 12 * 2) / 2  # nearest half year


def candidate_name(cv_text: str) -> str | None:
    """The first line of a CV is almost always the person's name (2-4 capitalised words)."""
    for line in cv_text.splitlines():
        line = line.strip()
        if not line:
            continue
        words = line.split()
        if 2 <= len(words) <= 4 and all(w[:1].isupper() and w.replace(".", "").isalpha() for w in words):
            return line
        return None
    return None


def scrub(text: str, name: str | None) -> str:
    """Remove contact details (emails, phones, links, handles) and the person's name."""
    text = _HANDLE.sub("", text)
    text = _EMAIL.sub("", text)
    text = _URL.sub("", text)
    text = _PHONE.sub("", text)
    if name:
        for part in {name, *name.split()}:
            if len(part) >= 3:
                text = re.sub(rf"\b{re.escape(part)}\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\(\s*\)|\[\s*\]", "", text)
    return re.sub(r"\s{2,}", " ", text).strip(" -|,;:")


_KEY_VALUE = re.compile(r"^\*{0,2}([A-Za-z][\w /&().-]{0,30}?)\*{0,2}\s*:\s*(.*)$")
_META_KEYS = re.compile(
    r"^(?:repo(?:sitory)?|github|git|link|links|url|demo|live|website|site|stack|tech(?:\s*stack)?|"
    r"technologies|tools|built\s+with|languages?|status|date|dates|duration|role|team|license|tags?)$",
    re.IGNORECASE,
)


_ONE_LINE_KEYS = re.compile(r"^(?:one[\s-]*line(?:r)?|summary|tl;?dr|description|about)$", re.IGNORECASE)
# Sentence end: . ! ? followed by space and a capital/quote/end; avoids "e.g. foo", "v1.2", "Node.js".
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(])")


def _first_full_sentence(text: str) -> str:
    return _SENTENCE_END.split(text.strip(), maxsplit=1)[0].strip()


def _lines(md: str):
    in_code = False
    for raw in md.splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line or line.startswith(("#", "|", "![", ">")):
            continue
        yield re.sub(r"^[-*•+]\s+|^\d+[.)]\s+", "", line)


def _first_sentence(md: str, person: str | None) -> str:
    """The project's one-liner: the full first sentence of its "One line:" field if it has one,
    else of its first real paragraph (>= 5 words). Never cut mid-sentence."""
    fallback = ""
    for line in _lines(md):
        key = None
        if m := _KEY_VALUE.match(line):
            key, line = m.group(1).strip(), m.group(2).strip()
        text = scrub(re.sub(r"[*_`]{1,3}", "", line), person)
        if key and _ONE_LINE_KEYS.match(key):
            if text:
                return _first_full_sentence(text)
            continue
        if key and _META_KEYS.match(key):
            continue
        if not fallback and len(text.split()) >= 5:
            fallback = _first_full_sentence(text)
    return fallback


@dataclass(frozen=True)
class ProjectFile:
    name: str
    skills: list[str]
    one_line: str


def parse_project(md: str, filename: str, person: str | None) -> ProjectFile:
    md = clean(md)[:MAX_TEXT]
    title = next((l.lstrip("#").strip() for l in md.splitlines() if l.startswith("#")), None)
    name = scrub(title or Path(filename).stem.replace("-", " ").replace("_", " "), person)[:80] or Path(filename).stem
    one_line = _first_sentence(md, person)
    counts = find_skills(md)
    skills = sorted(counts, key=lambda s: (-counts[s], s))
    return ProjectFile(name=name, skills=skills, one_line=one_line)


def skill_weights(sections: dict[str, str], projects_md: list[str]) -> dict[str, float]:
    """Weighted by prominence: experience > skills list > elsewhere; project files count most.

    The CV's own Projects section is deliberately ignored (only project files are evidence).
    """
    score: dict[str, float] = {}

    def add(counts: dict[str, int], weight: float) -> None:
        for skill, n in counts.items():
            score[skill] = score.get(skill, 0.0) + weight * min(n, 5)

    add(find_skills(sections.get("skills", "")), _WEIGHTS["skills"])
    add(find_skills(sections.get("experience", "")), _WEIGHTS["experience"])
    for other in ("education", "achievements", "responsibility", "other"):
        add(find_skills(sections.get(other, "")), _WEIGHTS["other"])
    for md in projects_md:
        add({s: 1 for s in find_skills(md)}, _WEIGHTS["project_file"])  # presence per project
    if not score:
        return {}
    top = max(score.values())
    return {k: round(v / top, 2) for k, v in sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))}


# --- build ---------------------------------------------------------------------------------

def profile_dir(home: Path) -> Path:
    return home / PROFILE_DIR


def init_dirs(home: Path) -> Path:
    base = profile_dir(home)
    ensure_private_dir(base)
    ensure_private_dir(base / PROJECTS_DIR)
    return base


def _inputs(home: Path) -> tuple[Path, list[Path]]:
    base = profile_dir(home)
    if not base.is_dir():
        raise ProfileError(f"{base} not found; run `mailwarden profile init` and add your CV and project files")
    check_private(base)
    pdfs = sorted(base.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not pdfs:
        raise ProfileError(f"no CV found: put your CV as a .pdf in {base}")
    projects = sorted((base / PROJECTS_DIR).glob("*.md")) if (base / PROJECTS_DIR).is_dir() else []
    for f in [pdfs[0], *projects]:
        check_private(f)  # personal files must be owner-only (chmod 600)
    return pdfs[0], projects


def build_profile(home: Path, *, locations: list[str], today: dt.date,
                  existing: dict | None = None, cv_text: str | None = None) -> dict:
    cv_path, project_paths = _inputs(home)
    text = cv_text if cv_text is not None else read_pdf_text(cv_path)
    if len(text.strip()) < 50:
        raise ProfileError("could not read text from the CV PDF (is it a scanned image?)")
    person = candidate_name(text)
    sections = split_sections(text)
    projects_md = [p.read_text("utf-8", errors="replace") for p in project_paths]
    projects = [parse_project(md, p.name, person) for md, p in zip(projects_md, project_paths, strict=True)]
    years = experience_years(sections.get("experience", ""), today)

    profile = {
        "skills": skill_weights(sections, projects_md),
        "experience_years": years,
        "seniority": "new_grad",
        "target_roles": list(DEFAULT_TARGET_ROLES),
        "avoid_roles": list(DEFAULT_AVOID_ROLES),
        "locations": list(locations),
        "remote_ok": True,
        "projects": [{"name": p.name, "skills": p.skills, "one_line": p.one_line} for p in projects],
    }
    for key in PRESERVED_KEYS:  # your hand-written sections survive a rebuild
        if existing and key in existing:
            profile[key] = existing[key]
    _validate_hand_sections(profile)
    extra = profile.get("extra_project_skills") or {}
    by_name = {str(k).strip().lower(): v for k, v in extra.items()}
    for proj in profile["projects"]:
        for skill in by_name.get(proj["name"].strip().lower(), []):
            skill = str(skill).strip().lower()
            if skill and skill not in proj["skills"]:
                proj["skills"].append(skill)
    return {k: profile[k] for k in KEY_ORDER if k in profile} | {
        k: v for k, v in profile.items() if k not in KEY_ORDER}


def unmatched_extra_projects(profile: dict) -> list[str]:
    """extra_project_skills entries whose project name matches no project file."""
    names = {p["name"].strip().lower() for p in profile.get("projects", [])}
    return [k for k in (profile.get("extra_project_skills") or {}) if str(k).strip().lower() not in names]


def _validate_hand_sections(profile: dict) -> None:
    so = profile.get("skill_overrides")
    if so is not None:
        if not isinstance(so, dict) or not all(
                isinstance(w, (int, float)) and not isinstance(w, bool) and 0 <= w <= 10 for w in so.values()):
            raise ProfileError("skill_overrides must map skill names to numbers (weights), e.g. go: 0.9")
    eps = profile.get("extra_project_skills")
    if eps is not None and (not isinstance(eps, dict) or not all(isinstance(v, list) for v in eps.values())):
        raise ProfileError("extra_project_skills must map project names to lists of skills")
    hl = profile.get("highlights")
    if hl is not None and not isinstance(hl, list):
        raise ProfileError("highlights must be a list")


def effective_skills(profile: dict) -> dict[str, float]:
    """What the scorer uses: auto-detected weights, replaced/extended by skill_overrides."""
    merged = {str(k).strip().lower(): float(v) for k, v in (profile.get("skills") or {}).items()}
    for k, v in (profile.get("skill_overrides") or {}).items():
        merged[str(k).strip().lower()] = float(v)
    return dict(sorted(merged.items(), key=lambda kv: (-kv[1], kv[0])))


# --- role matching ("/" separates alternatives) ------------------------------------------

def _norm_title(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9+#]+", " ", clean(text).lower()).strip() + " "


def role_alternatives(entry: str) -> list[str]:
    """ "sde / sde-1 / sde i" -> ["sde", "sde 1", "sde i"] (normalised)."""
    return [a.strip() for a in (_norm_title(part).strip() for part in str(entry).split("/")) if a.strip()]


def match_role(title: str, entries: list[str]) -> str | None:
    """The first entry any of whose "/"-separated alternatives appears in ``title`` as whole words."""
    t = _norm_title(title)
    for entry in entries:
        if any(f" {alt} " in t for alt in role_alternatives(entry)):
            return entry
    return None


HEADER = (
    "# mailwarden job-matching profile. Built by `mailwarden profile build` from your CV and\n"
    "# profile/projects/*.md. Edit freely. On rebuild, skills/experience_years/projects are\n"
    "# refreshed; seniority/target_roles/avoid_roles/locations/remote_ok keep your edits.\n"
    "# Never put contact details here: this file is given to the LLM for fit scoring.\n"
)


def dump(profile: dict) -> str:
    return HEADER + yaml.safe_dump(profile, sort_keys=False, allow_unicode=True, width=100)


GENERATED_KEYS = ("skills", "experience_years", "projects")
_TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*)\s*:(?:\s|$)")


def _blocks(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Top-level key -> (start, end) line span. Trailing blank/comment lines belong to the next key."""
    starts = [(i, m.group(1)) for i, line in enumerate(lines) if (m := _TOP_KEY.match(line))]
    spans = {}
    for n, (i, key) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        while end - 1 > i and (not lines[end - 1].strip() or lines[end - 1].lstrip().startswith("#")):
            end -= 1
        spans[key] = (i, end)
    return spans


def _dump_key(key: str, value) -> list[str]:
    return yaml.safe_dump({key: value}, sort_keys=False, allow_unicode=True, width=100).splitlines()


def render(existing_text: str | None, profile: dict) -> str:
    """profile.yaml text. With an existing file, only the generated blocks (skills,
    experience_years, projects) are replaced; every other line (your comments,
    formatting, order) is kept byte for byte."""
    if not existing_text or not existing_text.strip():
        return dump(profile)
    lines = existing_text.splitlines()
    for key in GENERATED_KEYS:
        new_block = _dump_key(key, profile[key])
        spans = _blocks(lines)
        if key in spans:
            start, end = spans[key]
            lines[start:end] = new_block
        elif key == "projects":
            lines += [""] + new_block
        else:  # skills / experience_years: insert before the first top-level key
            first = min((s for s, _ in spans.values()), default=len(lines))
            lines[first:first] = new_block
    present = set(_blocks(lines))
    for key, value in profile.items():  # defaults for sections your file doesn't have yet
        if key not in present and key not in GENERATED_KEYS:
            lines += [""] + _dump_key(key, value)
    text = "\n".join(lines) + "\n"
    parsed = yaml.safe_load(text)
    for key, value in profile.items():  # nothing of yours may change meaning
        if parsed.get(key) != value:
            raise ProfileError(f"could not update profile.yaml safely (section '{key}' would change); "
                               "fix its formatting or run with --dry-run to inspect")
    return text


def load_existing(home: Path) -> dict | None:
    path = home / PROFILE_FILE
    if not path.exists():
        return None
    check_private(path)
    data = yaml.safe_load(path.read_text("utf-8"))
    return data if isinstance(data, dict) else None


def diff(old_text: str, new_text: str) -> str:
    return "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
        fromfile="profile.yaml (current)", tofile="profile.yaml (new)",
    ))


def write(home: Path, text: str) -> Path:
    path = home / PROFILE_FILE
    if path.exists():
        write_private(home / (PROFILE_FILE + ".bak"), path.read_text("utf-8"))
    write_private(path, text)
    return path


def contact_leaks(text: str, person: str | None) -> list[str]:
    """What in the profile *data* looks like contact details (comments never reach the LLM)."""
    data = yaml.safe_load(text) or {}
    body = yaml.safe_dump(data, allow_unicode=True, width=10_000)
    leaks = []
    if _EMAIL.search(body):
        leaks.append("an email address")
    if _PHONE.search(body):
        leaks.append("a phone number")
    if _URL.search(body) or _HANDLE.search(body):
        leaks.append("a link or profile handle")
    if person and any(len(p) >= 3 and re.search(rf"\b{re.escape(p)}\b", body, re.IGNORECASE)
                      for p in {person, *person.split()}):
        leaks.append("your name")
    return leaks
