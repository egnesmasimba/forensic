"""A small query language shared by SQLite and Elasticsearch."""
import re

STOPWORDS = {
    "en": {"a", "an", "the", "of", "and", "or", "to", "in"},
    "fr": {"le", "la", "les", "de", "des", "et", "un", "une"},
    "de": {"der", "die", "das", "und", "ein", "eine"},
    "es": {"el", "la", "los", "las", "de", "y", "un", "una"},
}


def parse_query(query, language=None):
    stops = set()
    if language:
        if language not in STOPWORDS:
            raise ValueError("language must be en, fr, de, or es")
        stops = STOPWORDS[language]
    groups, current = [], []
    cursor = 0
    while cursor < len(query):
        if query[cursor].isspace():
            cursor += 1
            continue
        excluded = query[cursor] == "-"
        if excluded:
            cursor += 1
        phrase = cursor < len(query) and query[cursor] == '"'
        if phrase:
            end = query.find('"', cursor + 1)
            if end < 0:
                raise ValueError("Close the quoted phrase")
            value = query[cursor + 1:end]
            cursor = end + 1
            if cursor < len(query) and not query[cursor].isspace():
                raise ValueError("Separate search terms with spaces")
            fuzzy = False
        else:
            end = cursor
            while end < len(query) and not query[end].isspace():
                end += 1
            value, cursor = query[cursor:end], end
            fuzzy = value.endswith("~")
            if fuzzy:
                value = value[:-1]
        if value == "OR" and not phrase and not excluded and not fuzzy:
            if not current or not any(not term[1] for term in current):
                raise ValueError("OR needs a search term on each side")
            groups.append(current)
            current = []
            continue
        words = re.findall(r"\w+", value, re.UNICODE)
        if fuzzy and (phrase or len(words) != 1 or not 4 <= len(words[0]) <= 16):
            raise ValueError("A fuzzy term is one word of 4 to 16 characters followed by ~")
        if not words or any(len(word) > 64 for word in words):
            raise ValueError("Search terms must contain letters or numbers and be at most 64 characters")
        if not phrase and not fuzzy and len(words) == 1 and words[0].casefold() in stops:
            continue
        current.append((" ".join(words), excluded, phrase, fuzzy))
        if sum(len(g) for g in groups) + len(current) > 20:
            raise ValueError("Use at most 20 search terms")
    if not current or not any(not term[1] for term in current):
        raise ValueError("Enter a search term; exclusions alone are not supported")
    return groups + [current]


def fts_query(groups):
    alternatives = []
    for group in groups:
        positive, negative = [], []
        for term, excluded, phrase, fuzzy in group:
            words = term.split()
            if fuzzy:
                expression = '"' + words[0][:3] + '"*'
            else:
                expression = '"' + ' '.join(words) + '"' if phrase else " AND ".join('"' + word + '"' for word in words)
            (negative if excluded else positive).append("(" + expression + ")")
        expression = " AND ".join(positive)
        for term in negative:
            expression = "(" + expression + ") NOT " + term
        alternatives.append("(" + expression + ")")
    return " OR ".join(alternatives)


def elastic_query(groups, filters):
    alternatives = []
    for group in groups:
        must, excluded = [], []
        for term, negative, phrase, fuzzy in group:
            match = {"multi_match": {"query": term, "fields": ["title^8", "headers_text^5", "captions_text^4", "values_text^3", "body"],
                                     "type": "phrase" if phrase else "cross_fields"}}
            if not phrase:
                match["multi_match"]["operator"] = "and"
            if fuzzy:
                match["multi_match"]["fuzziness"] = 1
            (excluded if negative else must).append(match)
        alternatives.append({"bool": {"must": must, "must_not": excluded}})
    return {"bool": {"should": alternatives, "minimum_should_match": 1, "filter": filters}}


def snippet(document, groups):
    body = " ".join((document.get("body", ""), document.get("headers_text", ""),
                     document.get("captions_text", ""), document.get("values_text", "")))
    body = " ".join(body.split())
    positive = [term.split()[0] for group in groups for term, negative, *_ in group if not negative]
    positions = [body.lower().find(term.lower()) for term in positive]
    position = min((p for p in positions if p >= 0), default=0)
    start = max(0, position - 80)
    return ("…" if start else "") + body[start:start + 300] + ("…" if start + 300 < len(body) else "")


def _edits(left, right):
    if left == right:
        return 0
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, 1):
        current = [index]
        for column, right_char in enumerate(right, 1):
            cost = 0 if left_char == right_char else 1
            current.append(min(current[-1] + 1, previous[column] + 1, previous[column - 1] + cost))
        previous = current
    return previous[-1]


def within_one(term, text):
    target = term.casefold()
    for token in re.findall(r"\w+", text, re.UNICODE):
        folded = token.casefold()
        if abs(len(folded) - len(target)) <= 1 and _edits(folded, target) <= 1:
            return True
    return False


def document_text(document):
    return " ".join(str(document.get(name, "")) for name in ("title", "body", "headers_text", "captions_text", "values_text"))


def _term_found(term, phrase, fuzzy, text):
    if fuzzy:
        return within_one(term, text)
    folded = text.casefold()
    if phrase:
        return term.casefold() in folded
    return all(word.casefold() in folded for word in term.split())


def fuzzy_hit(groups, document):
    """Keep a hit when one complete alternative matches, using edit distance for ~ terms."""
    if not any(term[3] for group in groups for term in group):
        return True
    text = document_text(document)
    for group in groups:
        if all(_term_found(term, phrase, fuzzy, text) != excluded for term, excluded, phrase, fuzzy in group):
            return True
    return False
