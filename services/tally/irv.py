"""
Instant-Runoff Voting (IRV) implementation.
Single-winner ranked-choice voting.
"""

from collections import Counter
from typing import List, Dict, Any


def run_irv(ballots: List[List[str]], candidates: List[str]) -> Dict[str, Any]:
    active  = set(candidates)
    rounds  = []
    working = [list(b) for b in ballots]

    while True:
        first_prefs = Counter()
        for ballot in working:
            for choice in ballot:
                if choice in active:
                    first_prefs[choice] += 1
                    break

        counts = {c: first_prefs.get(c, 0) for c in active}
        total  = sum(counts.values())

        if total == 0:
            rounds.append({"counts": counts, "eliminated": None})
            return {"winner": None, "rounds": rounds}

        for candidate, count in counts.items():
            if count > total / 2:
                rounds.append({"counts": counts, "eliminated": None})
                return {"winner": candidate, "rounds": rounds}

        if len(active) == 1:
            rounds.append({"counts": counts, "eliminated": None})
            return {"winner": next(iter(active)), "rounds": rounds}

        min_votes    = min(counts.values())
        to_eliminate = [c for c, v in counts.items() if v == min_votes]

        if len(to_eliminate) >= len(active):
            rounds.append({"counts": counts, "eliminated": "TIE"})
            return {"winner": None, "rounds": rounds}

        for c in to_eliminate:
            active.discard(c)
        rounds.append({"counts": counts, "eliminated": ", ".join(to_eliminate)})


def compute_all_results(roles, submitted_ballots) -> List[Dict[str, Any]]:
    results = []
    for role in sorted(roles, key=lambda r: r.idx):
        role_id      = str(role.id)
        role_ballots = [
            b.votes[role_id]
            for b in submitted_ballots
            if b.votes and role_id in b.votes and b.votes[role_id]
        ]
        irv = run_irv(role_ballots, role.candidates)
        results.append({
            "role_id":       role_id,
            "role":          role.role,
            "candidates":    role.candidates,
            "total_ballots": len(role_ballots),
            "winner":        irv["winner"],
            "rounds":        irv["rounds"],
        })
    return results
