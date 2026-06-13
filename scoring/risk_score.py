def calculate_score(results: list) -> int:
    score = 0
    weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 4}
    for r in results:
        score += weights.get(r.get("risk", "LOW"), 4)
    return min(score, 100)
