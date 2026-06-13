import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(keyword):
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 2  # keep small (API is slow)
        }

        response = requests.get(NVD_API_URL, params=params, timeout=8)

        if response.status_code != 200:
            return []

        data = response.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            desc = "No description"
            if cve.get("descriptions"):
                desc = cve["descriptions"][0]["value"]

            results.append((cve_id, desc[:120]))

        return results

    except Exception:
        return []
