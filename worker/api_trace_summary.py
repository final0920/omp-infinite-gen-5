"""Aggregate debugger-observed API calls into taxonomy counts and per-thread chains.

The call list is evidence of entry breakpoint hits in one run (E1). The category
and chain rows are a taxonomy interpretation of those hits (E0): co-occurrence is
not proof of intent, successful completion, or complete coverage.
"""
from __future__ import annotations

from behavior_rules import API_CATEGORIES, CHAINS, DISTINCT_RULES, TAXONOMY_VERSION, api_category, canonical

SCHEMA = "ig5.apiTraceBehavior.v1"
SUMMARY_VERSION = 1
NOTE = ("E1 call list (breakpoint entries in this run) aggregated under taxonomy v%d; "
        "the category/chain rows are E0 leads, not proof of intent, completion or full coverage." % TAXONOMY_VERSION)


def _name(call):
    name = call.get("api")
    return name if isinstance(name, str) and name else None


def _thread(call):
    thread = call.get("threadId")
    return thread if isinstance(thread, int) and not isinstance(thread, bool) and thread > 0 else None


def _category_rows(calls):
    rows = {}
    for call in calls:
        name = _name(call)
        if not name:
            continue
        key = canonical(name)
        if not key:
            continue
        row = rows.setdefault(key, {"category": API_CATEGORIES[key], "calls": 0, "threads": set(),
                                    "apis": set(), "firstCall": call.get("index"), "lastCall": call.get("index")})
        row["calls"] += 1
        row["apis"].add(name)
        thread = _thread(call)
        if thread is not None:
            row["threads"].add(thread)
        if isinstance(call.get("index"), int):
            row["firstCall"] = min(row["firstCall"], call["index"]) if isinstance(row["firstCall"], int) else call["index"]
            row["lastCall"] = max(row["lastCall"], call["index"]) if isinstance(row["lastCall"], int) else call["index"]
    from behavior_rules import WEAK_CATEGORIES
    return sorted(({"category": row["category"], "calls": row["calls"], "distinctApis": len(row["apis"]),
                    "apis": sorted(row["apis"]), "threads": sorted(row["threads"]),
                    "firstCall": row["firstCall"], "lastCall": row["lastCall"],
                    "weak": row["category"] in WEAK_CATEGORIES} for row in rows.values()),
                  key=lambda row: (row["weak"], row["category"]))


def _thread_calls(calls):
    groups = {}
    for call in calls:
        thread = _thread(call)
        if thread is not None and _name(call):
            groups.setdefault(thread, []).append(call)
    return groups


def _chain_rows(calls):
    rows = []
    for thread, rows_in_thread in sorted(_thread_calls(calls).items()):
        for chain in CHAINS:
            matched = []
            for group in chain["groups"]:
                hit = next((call for call in rows_in_thread if canonical(_name(call)) in group), None)
                if hit is None:
                    break
                matched.append(hit)
            else:
                rows.append({"id": chain["id"], "strength": chain["strength"], "label": chain["label"],
                             "threadId": thread, "threadScoped": True,
                             "callIndices": [call.get("index") for call in matched],
                             "apis": [call.get("api") for call in matched]})
        for rule in DISTINCT_RULES:
            names = sorted({canonical(_name(call)) for call in rows_in_thread
                            if canonical(_name(call)) and API_CATEGORIES.get(canonical(_name(call))) == rule["category"]})
            if len(names) >= rule["minimum"]:
                rows.append({"id": rule["id"], "strength": rule["strength"], "label": rule["label"],
                             "threadId": thread, "threadScoped": True, "category": rule["category"],
                             "distinctApis": names, "minimumDistinctApis": rule["minimum"]})
    return rows


def summarize(calls):
    if not isinstance(calls, list) or len(calls) > 4096:
        raise ValueError("calls must be a list of at most 4096 entries")
    uncategorized = sorted({name for call in calls for name in [_name(call)]
                            if name and canonical(name) is None})
    return {"schema": SCHEMA, "version": SUMMARY_VERSION, "taxonomyVersion": TAXONOMY_VERSION,
            "callCount": len(calls), "categories": _category_rows(calls), "chains": _chain_rows(calls),
            "uncategorizedApis": uncategorized[:64], "uncategorizedCount": len(uncategorized),
            "threadScoped": True, "evidenceLevel": "E0", "note": NOTE}
