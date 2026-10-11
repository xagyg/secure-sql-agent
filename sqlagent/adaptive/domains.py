# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Domains of Discourse (DoD).
#
# The whole (security-filtered) schema is the agent's Universe of
# Discourse (UoD). A Domain of Discourse is a named subset of it - Sales,
# Purchasing, HR, ... - plus the words that point towards it.
#
# For each question the agent works out WHICH domain it is about, using
# three signals:
#
#   Who   - the user's roles (from the SecurityContext, or a [who=...] tag
#           in the demo), matched to each domain's role affinities.
#   What  - the question itself: does it name the domain ("in purchasing")
#           and how well do the domain's tables match its words?
#   Where - where the user is asking from, given as a [where=...] tag at
#           the end of the question, e.g. "[where=financials data entry]".
#
# The chosen domain only changes WHERE the schema search starts. It never
# changes what the user may see: the catalog is already filtered by the
# SecurityContext, a domain table the role can't access simply isn't in
# it, and every ABC still runs on the generated SQL.
#
# Everything here is deterministic. The LLM never chooses the domain.

import re
from dataclasses import dataclass, field

from sqlagent.controls.security_utils import full_table_name
from sqlagent.adaptive.text_match import FULL_NAME_MATCH, GENERIC_TERMS, phrase_matches, tokenize


# ---------------------------------------------------------------------------
# Domain definitions
# ---------------------------------------------------------------------------
# The domains, role_aliases (friendly names for role codes) and
# function_aliases (screen codes such as PUR0410) are part of the
# semantic model: config/semantic/northwind/domains.yaml documents each key. The
# resolver reads them from catalog.semantic, or from the arguments, as
# plain dicts:
#
#   domains           key -> {label, aliases, tables, roles, where, hops,
#                             fallback_tables}
#   role_aliases      role -> set of friendly names
#   function_aliases  CODE -> set of location names

# ---------------------------------------------------------------------------
# Tuning
# ---------------------------------------------------------------------------

# Signal weights. When a signal is absent (no [where=...] tag, say) its
# weight is shared among the signals that are present, so questions
# without a tag aren't penalised.
WEIGHT_WHAT = 0.45
WEIGHT_WHERE = 0.35
WEIGHT_WHO = 0.20

# Bonus for the domain used on the previous turn, so follow-ups such as
# "and which of those were late?" stay in the same area.
STICKY_BONUS = 0.10

# Weak evidence never moves a conversation. When the question names no
# table (in full or by alias) and no domain, and there is no [where=...]
# tag, the only What signal is column words ("phone") or partial names.
# Normalising would still turn that into "what 1.00" and outvote the
# sticky bonus, so e.g. "What is Maria's phone number?" after a question
# about customers jumped to Purchasing (suppliers.phone) because
# customers.phone is hidden from the role. With weak evidence and a
# previous domain, the agent stays in the previous domain instead.
WEAK_EVIDENCE_FOLLOW_UP = True

# A question that names the domain ("in purchasing") is worth two tables
# named in full (see FULL_NAME_MATCH in text_match.py).
EXPLICIT_DOMAIN_POINTS = 40

# Points per word of a matched location phrase. Longer, more specific
# phrases ("purchase order entry") beat single words ("entry").
WHERE_PHRASE_POINTS = 10

# Decision rule.
MIN_DOMAIN_SCORE = 0.25   # below this, no domain: search the whole UoD
BLEND_MARGIN = 0.15       # top two closer than this: use both domains

# Demo only: lets the person asking set Who with "[who=buyer]". This
# affects ROUTING only - never authorisation, which always comes from the
# authenticated SecurityContext. Turn off in any real deployment.
ALLOW_WHO_TAG = True

_TAG_PATTERN = re.compile(r"\[\s*(where|who)\s*=\s*([^\]\[]{1,80})\]", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Context tags
# ---------------------------------------------------------------------------

@dataclass
class QuestionContext:
    question: str                 # the question with tags removed
    where: str | None = None
    who: str | None = None


def parse_context_tags(text):
    """
    Pull [where=...] and [who=...] tags out of a question.

    Returns a QuestionContext whose .question has the tags removed. The
    tags are only ever used for deterministic matching; they are never
    sent to the LLM or stored in the conversation history.
    """
    where = None
    who = None

    for match in _TAG_PATTERN.finditer(text):
        key = match.group(1).lower()
        value = " ".join(match.group(2).split())
        if not value:
            continue
        if key == "where":
            where = value
        elif key == "who" and ALLOW_WHO_TAG:
            who = value

    question = " ".join(_TAG_PATTERN.sub(" ", text).split())
    return QuestionContext(question=question, where=where, who=who)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass
class DomainScore:
    key: str
    label: str
    what: float = 0.0     # normalised 0..1
    where: float = 0.0    # normalised 0..1
    who: float = 0.0      # 0..1 (affinity, not normalised)
    sticky: bool = False
    total: float = 0.0


@dataclass
class DomainDecision:
    domains: list = field(default_factory=list)   # chosen domain keys
    labels: dict = field(default_factory=dict)    # key -> label, for display
    mode: str = "none"        # "single" | "blended" | "follow_up" | "none"
    scores: list = field(default_factory=list)    # DomainScore, best first
    signals: dict = field(default_factory=dict)   # which signals were present

    @property
    def label(self):
        return " + ".join(self.labels.get(k, k) for k in self.domains) or None

    def summary(self):
        """One line for the console / audit log."""
        if not self.domains:
            return "no domain - searching the whole schema"

        def fmt(s):
            return (f"{s.label} {s.total:.2f} "
                    f"(what {s.what:.2f}, where {s.where:.2f}, who {s.who:.2f}"
                    f"{', sticky' if s.sticky else ''})")

        chosen = [s for s in self.scores if s.key in self.domains]
        others = [s for s in self.scores if s.key not in self.domains and s.total > 0]
        mode = self.mode
        if self.signals.get("weak_evidence"):
            mode += " (weak evidence - staying in previous domain)"
        text = f"{mode}: " + "; ".join(fmt(s) for s in chosen)
        if others:
            text += f" | runner-up: {fmt(others[0])}"
        return text


class DomainResolver:
    """
    Scores every domain against Who / What / Where and picks the target.

    Uses the catalog's own tokenizer and table scoring, so a domain
    "matches" a question in exactly the same way a table does.
    """

    def __init__(self, catalog, domains=None, role_aliases=None,
                 function_aliases=None):
        self.catalog = catalog
        semantic = getattr(catalog, "semantic", None)
        self.domains = (
            domains if domains is not None
            else (semantic.domains if semantic else {}))
        self.role_aliases = (
            role_aliases if role_aliases is not None
            else (semantic.role_aliases if semantic else {}))
        self.function_aliases = (
            function_aliases if function_aliases is not None
            else (semantic.function_aliases if semantic else {}))
        self.domain_tables = {}      # key -> set of full table names
        self.domain_fallbacks = {}   # key -> set of full table names
        self.refresh()

    # -- setup ---------------------------------------------------------

    def refresh(self):
        """Map each domain's table names onto the loaded (authorised)
        catalog. Call after catalog.refresh()."""
        def resolve(names, key, what):
            found = set()
            for table in names:
                match = self.catalog.resolve_table_name(table)
                if match:
                    found.add(match)
                else:
                    print(f"[domain] {key}: {what} '{full_table_name(table)}' "
                          "not available - skipped")
            return found

        self.domain_tables = {}
        self.domain_fallbacks = {}
        for key, domain in self.domains.items():
            self.domain_tables[key] = resolve(domain["tables"], key, "table")
            self.domain_fallbacks[key] = resolve(
                domain.get("fallback_tables", ()), key, "fallback table")

        usable = [k for k, t in self.domain_tables.items() if t]
        print(f"[domain] {len(usable)} domain(s) available: {', '.join(usable) or 'none'}")

    # -- matching helpers ----------------------------------------------

    def _tok(self, text):
        return tokenize(text)

    def _phrase_matches(self, phrase, terms):
        return phrase_matches(phrase, terms)

    @staticmethod
    def _phrase_len(phrase):
        return len([p for p in re.split(r"[_\s]+", phrase) if p])

    def _canonical_roles(self, roles, who_text):
        """Security roles (exact, case-insensitive) plus any role the
        [who=...] tag names, by role name or role alias."""
        canonical = {r.lower() for r in roles}

        if who_text:
            terms = self._tok(who_text)
            known = set(self.role_aliases)
            for domain in self.domains.values():
                known |= set(domain.get("roles", {}))
            for role in known:
                names = {role} | self.role_aliases.get(role, set())
                if any(self._phrase_matches(n, terms) for n in names):
                    canonical.add(role.lower())

        return canonical

    def _where_terms(self, where_text):
        """Tokenise the location, expanding a function code (PUR0410) to
        its friendly names first."""
        text = where_text
        for code, names in self.function_aliases.items():
            if where_text.strip().lower() == code.lower():
                text = " ".join(n.replace("_", " ") for n in names)
                break
        return self._tok(text)

    # -- scoring -------------------------------------------------------

    def resolve(self, question, roles=(), where=None, who=None,
                previous_domain=None):
        q_terms = self._tok(question) - GENERIC_TERMS
        # Location names keep words like "records" or "details" that are
        # generic in a question, so GENERIC_TERMS isn't removed here.
        where_terms = self._where_terms(where) if where else set()
        role_set = self._canonical_roles(roles, who)

        # Score every authorised table against the question once.
        table_scores = {
            name: self.catalog.score_table(table, q_terms)
            for name, table in self.catalog.tables.items()
        }
        where_table_scores = {}
        if where_terms:
            where_table_scores = {
                name: self.catalog.score_table(table, where_terms)
                for name, table in self.catalog.tables.items()
            }

        # Where: which location phrases does the tag match? A phrase
        # that is part of a longer matched phrase is dropped, so
        # "purchase order entry" counts for Purchasing, not also as
        # "order entry" for Sales.
        where_phrases = {}
        if where_terms:
            matched = {
                phrase
                for domain in self.domains.values()
                for phrase in set(domain.get("where", ())) | set(domain["aliases"])
                if self._phrase_matches(phrase, where_terms)
            }
            words = {p: set(re.split(r"[_\s]+", p.lower())) for p in matched}
            where_phrases = {
                p for p in matched
                if not any(words[p] < words[q] for q in matched)
            }

        raw = {}
        named_domain = False   # the question names a domain ("in purchasing")
        for key, domain in self.domains.items():
            tables = self.domain_tables.get(key)
            if not tables:
                continue   # nothing this user can see in that domain

            # What: explicit mention + the domain's best-matching tables.
            # Top table counts fully, 2nd half, 3rd a quarter, so a big
            # domain can't win just by having lots of weak matches.
            ranked = sorted((table_scores[t] for t in tables), reverse=True)[:3]
            what = sum(s * w for s, w in zip(ranked, (1.0, 0.5, 0.25)))
            if any(self._phrase_matches(a, q_terms) for a in domain["aliases"]):
                what += EXPLICIT_DOMAIN_POINTS
                named_domain = True

            # Where: the longest location phrase this domain owns. If the
            # tag matched no phrase anywhere, fall back to the tables it
            # names (e.g. "[where=shippers]").
            where_score = 0.0
            if where_phrases:
                own = where_phrases & (set(domain.get("where", ())) | set(domain["aliases"]))
                if own:
                    where_score = WHERE_PHRASE_POINTS * max(self._phrase_len(p) for p in own)
            elif where_terms:
                where_score = max((where_table_scores[t] for t in tables), default=0)

            # Who: the strongest affinity among the user's roles.
            affinities = {r.lower(): v for r, v in domain.get("roles", {}).items()}
            who_score = max((affinities.get(r, 0.0) for r in role_set), default=0.0)

            raw[key] = (what, where_score, who_score)

        if not raw:
            return DomainDecision(signals={})

        max_what = max(v[0] for v in raw.values())
        max_where = max(v[1] for v in raw.values())
        has_who = any(v[2] > 0 for v in raw.values())

        present = {
            "what": max_what > 0,
            "where": max_where > 0,
            "who": has_who,
        }
        weights = {"what": WEIGHT_WHAT, "where": WEIGHT_WHERE, "who": WEIGHT_WHO}
        active = sum(w for k, w in weights.items() if present[k])

        scores = []
        for key, (what, where_score, who_score) in raw.items():
            s = DomainScore(
                key=key,
                label=self.domains[key]["label"],
                what=(what / max_what) if max_what else 0.0,
                where=(where_score / max_where) if max_where else 0.0,
                who=who_score,
                sticky=(key == previous_domain),
            )
            if active:
                s.total = (
                    weights["what"] * s.what
                    + weights["where"] * s.where
                    + weights["who"] * s.who
                ) / active
            if s.sticky:
                s.total += STICKY_BONUS
            scores.append(s)

        scores.sort(key=lambda s: s.total, reverse=True)
        decision = DomainDecision(
            scores=scores, signals=present,
            labels={k: d["label"] for k, d in self.domains.items()})

        # Strong evidence: a table named in full or by alias (any
        # authorised table, inside a domain or not), a domain named, or a
        # matched location.
        strong = (
            named_domain
            or present["where"]
            or max(table_scores.values(), default=0) >= FULL_NAME_MATCH
        )

        if not active or (WEAK_EVIDENCE_FOLLOW_UP and not strong
                          and previous_domain in raw):
            # No signal at all ("now by month"), or only weak evidence
            # ("what is Maria's phone number?"). Stay where the
            # conversation already is, if anywhere.
            if previous_domain in raw:
                decision.domains = [previous_domain]
                decision.mode = "follow_up"
                if active:
                    decision.signals["weak_evidence"] = True
            return decision

        best = scores[0]
        if best.total < MIN_DOMAIN_SCORE:
            return decision   # too weak: whole UoD, as before

        if len(scores) > 1 and best.total - scores[1].total < BLEND_MARGIN \
                and scores[1].total >= MIN_DOMAIN_SCORE:
            # Too close to call. At Northwind scale, just use both. On a
            # large ERP this is where the agent would ask the user which
            # area they mean.
            decision.domains = [best.key, scores[1].key]
            decision.mode = "blended"
        else:
            decision.domains = [best.key]
            decision.mode = "single"

        return decision

    # -- schema scope --------------------------------------------------

    def scope(self, decision):
        """Tables, fallback tables and hop limit for a decision, or None
        when no domain was chosen."""
        if not decision.domains:
            return None
        tables, fallbacks, hops = set(), set(), 1
        for key in decision.domains:
            tables |= self.domain_tables.get(key, set())
            fallbacks |= self.domain_fallbacks.get(key, set())
            hops = max(hops, self.domains[key].get("hops", 1))
        return tables, fallbacks, hops
