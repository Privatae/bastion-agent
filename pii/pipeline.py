"""Sterilization pipeline — deterministic control flow, LLM as sensor.

Stages (docs/pii-sterilization.md):
  1. rules pass    detect.detect() — precision anchors, model-free
  2. LLM pass      llmclient.extract() — recall for contextual PII
  3. grounding     every LLM span must occur verbatim in the input;
                   ungrounded spans are dropped and counted, never trusted
  4. replacement   script-side, longest value first, every occurrence
                   (plain substring, inside longer words too); overlapping
                   matches merge into one token; never inside an existing
                   token; placeholder-shaped text in the input is escaped
                   first (all of it for raw documents, only what the vault
                   does not hold otherwise); tokens minted by the vault
                   (stable per scope)
  5. residual loop rules re-run on the output until clean (bounded);
                   any residual is tokenized, not just reported
  6. LLM verify    optional second model pass over the sterilized text;
                   grounded hits go through replacement again

The model proposes; this module disposes. Every mutation of the text
happens in replace_values(), which guarantees non-PII bytes are
byte-identical to the input.
"""

import re

from . import detect

TOKEN_RE = re.compile(r"\[PII_([A-Z_]+)_(\d+)\]")
# a token's name without its brackets; as a value it could only ever come
# from the model reading an already-sterilized text
BARE_TOKEN_RE = re.compile(r"PII_[A-Z_]+_\d+")

_MAX_RESIDUAL_ROUNDS = 3


def _usable(value: str, typ: str) -> bool:
    if typ not in detect.PII_TYPES:
        return False
    if len(value) < 2:
        return False
    if TOKEN_RE.search(value) or BARE_TOKEN_RE.search(value):
        return False
    return True


def ground(proposed, text):
    """Split LLM proposals into (grounded, dropped_count)."""
    grounded, dropped = [], 0
    for value, typ in proposed:
        if value and value in text and _usable(value, typ):
            grounded.append((value, typ))
        else:
            dropped += 1
    return grounded, dropped


def _occurrences(value, text, blocked):
    """Every occurrence of value, overlapping ones included ("aba" twice in
    "ababa"), minus any that overlap a blocked span. Overlapping hits are
    merged by the caller, so no fragment of a self-overlapping value is
    left between two tokens."""
    spans = []
    i = text.find(value)
    while i >= 0:
        end = i + len(value)
        if not any(i < be and end > bs for bs, be in blocked):
            spans.append((i, end))
        i = text.find(value, i + 1)
    return spans


def replace_values(text, values, scope, vault, block_tokens=True):
    """Replace every occurrence of each value with its vault token.

    Plain substring matching: a value is replaced inside longer words too
    ("Garcia" in "Garcias", "Marisol" in "Marisol_resume.pdf"), because a
    missed inflection is a leak and an over-eager match only costs
    readability. Longest value first, so "John Smith" is consumed before
    "John" can split it. No match may overlap a token already in the text,
    so a value like "PERSON" cannot break a placeholder apart.

    Two matches that partly overlap (neither contains the other) become one
    token over their union: tokenizing one would leave the other's
    remainder in the clear. It takes the longer value's type.

    Every byte outside a replaced span is copied unchanged.

    block_tokens=False is only for escaping placeholder-shaped text in the
    input (see sterilize), where the literal itself is the value to replace.
    """
    types, order = {}, {}
    for value, typ in values:
        if value and value not in types:
            types[value] = typ
            order[value] = len(order)
    blocked = [m.span() for m in TOKEN_RE.finditer(text)] if block_tokens else []
    matches = []
    for value in sorted(types, key=lambda v: (-len(v), order[v])):
        matches.extend((s, e, value) for s, e in _occurrences(value, text, blocked))

    # union overlapping matches; the longest (then earliest-given) value names
    # the group, and a group wider than it is a merged value of its own
    groups = []
    for s, e, value in sorted(matches):
        if groups and s < groups[-1][1]:
            g = groups[-1]
            g[1] = max(g[1], e)
            g[2].append(value)
        else:
            groups.append([s, e, [value]])

    spans = []
    for s, e, members in groups:
        lead = min(members, key=lambda v: (-len(v), order[v]))
        value = text[s:e]
        if value not in types:
            types[value] = types[lead]
            order[value] = order[lead]
        spans.append((s, e, value))

    tokens, applied = {}, []
    for value in sorted({v for _, _, v in spans}, key=lambda v: (-len(v), order[v])):
        tokens[value] = vault.token_for(scope, types[value], value)
        applied.append({"token": tokens[value], "type": types[value]})

    parts, pos = [], 0
    for s, e, value in spans:
        parts.append(text[pos:s])
        parts.append(tokens[value])
        pos = e
    parts.append(text[pos:])
    return "".join(parts), applied


def sterilize(text, scope, vault, llm_extract, llm_verify=None, escape_held_literals=False):
    """Returns (sterilized_text, result_dict).

    escape_held_literals: escape every placeholder-shaped string in the
    input, even one the vault holds for this scope. For raw documents,
    which never contain this service's own output: a document that quotes
    "[PII_EMAIL_1]" must not rehydrate to another document's email. Off for
    callers that send already-sterilized text back (a stored conversation on
    every save), where a held placeholder is that token and must stay it.
    """
    rule_values = [(f.value, f.type) for f in detect.detect(text)]

    llm_values, ungrounded = ground(llm_extract(text), text)

    # Placeholder-shaped text that is not one of this scope's tokens is
    # escaped as a value of its own, so rehydrate gives the literal back
    # instead of leaving it to collide with a token minted later. Unless the
    # caller asks for every literal to be escaped, one the vault holds passes
    # through untouched: already-sterilized text is sterilized again (a
    # stored conversation on every save), and its tokens must stay the same
    # tokens. Each distinct literal is looked up once.
    shapes = {m.group(0) for m in TOKEN_RE.finditer(text)}
    if not escape_held_literals:
        shapes = {lit for lit in shapes if vault.value_for(scope, lit) is None}
    literals = [(lit, "OTHER") for lit in sorted(shapes)]
    out, escaped = replace_values(text, literals, scope, vault, block_tokens=False)

    # Rules first: replace_values keeps the first type seen for a value,
    # and on a duplicate the rule's type is the higher-precision one.
    out, applied = replace_values(out, rule_values + llm_values, scope, vault)

    # every finding a later round tokenizes is counted, not only the last
    # round's: the round that comes back clean must not reset the total
    residual = 0
    for _ in range(_MAX_RESIDUAL_ROUNDS):
        leftover = [(f.value, f.type) for f in detect.detect(out)]
        if not leftover:
            break
        residual += len(leftover)
        out, more = replace_values(out, leftover, scope, vault)
        applied.extend(more)

    verify_hits = 0
    if llm_verify is not None:
        vgrounded, _ = ground(llm_verify(out), out)
        if vgrounded:
            # count what was replaced, not what was proposed: a grounded value
            # that only occurs inside an existing token replaces nothing
            out, more = replace_values(out, vgrounded, scope, vault)
            verify_hits = len(more)
            applied.extend(more)

    return out, {
        "findings": applied,
        "stats": {
            "rules": len(rule_values),
            "llm": len(llm_values),
            "llm_ungrounded": ungrounded,
            "residual_tokenized": residual,
            "verify_tokenized": verify_hits,
            "literal_tokens_escaped": len(escaped),
        },
    }


def rehydrate(text, scope, vault):
    """Replace vault tokens with their original values. Unknown tokens are
    left in place and reported — never guessed."""
    unknown = []
    restored = 0

    def sub(m):
        nonlocal restored
        value = vault.value_for(scope, m.group(0))
        if value is None:
            unknown.append(m.group(0))
            return m.group(0)
        restored += 1
        return value

    out = TOKEN_RE.sub(sub, text)
    return out, {"restored": restored, "unknown_tokens": sorted(set(unknown))}
