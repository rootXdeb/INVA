import json
from datetime import datetime

def save_report(target, results, score):
    report = {
        "target": target,
        "timestamp": str(datetime.now()),
        "risk_score": score,
        "findings": results
    }

    filename = f"report_{target}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return filename


