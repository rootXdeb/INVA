import threading
import uuid
import json
import os
from flask import Flask, render_template, request, jsonify, send_file, abort
from database.db import init_db, get_all_scans, get_scan
from core.engine import run_scan

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

app = Flask(__name__, template_folder="templates", static_folder="static")

# In-memory scan job tracker
_jobs = {}


def _job_worker(job_id: str, ip: str):
    def progress(msg):
        _jobs[job_id]["messages"].append(msg)
        _jobs[job_id]["status"] = "running"

    try:
        result = run_scan(ip, progress_cb=progress)
        _jobs[job_id]["result"] = result
        _jobs[job_id]["status"] = "done"
    except Exception as e:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(e)


@app.route("/")
def index():
    scans = get_all_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan/start", methods=["POST"])
def start_scan():
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "running", "messages": [], "result": None, "error": None}

    t = threading.Thread(target=_job_worker, args=(job_id, ip), daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/scan/status/<job_id>")
def scan_status(job_id):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status":   job["status"],
        "messages": job["messages"],
        "error":    job.get("error"),
    })


@app.route("/scan/result/<job_id>")
def scan_result(job_id):
    job = _jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Result not ready"}), 404
    return jsonify({"scan_id": job["result"]["scan_id"]})


@app.route("/report/<int:scan_id>")
def view_report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    scan["findings"]     = json.loads(scan["findings"])
    scan["compliance"]   = json.loads(scan["compliance"])
    scan["threat_intel"] = json.loads(scan["threat_intel"])
    # Expose resolved IP separately for the template
    ti = scan["threat_intel"]
    scan["ip"] = ti.get("ip", scan["target"])
    return render_template("report.html", scan=scan)


@app.route("/report/<int:scan_id>/pdf")
def download_pdf(scan_id):
    scan = get_scan(scan_id)
    if not scan or not scan.get("pdf_file"):
        abort(404)
    pdf_path = scan["pdf_file"]
    if not os.path.exists(pdf_path):
        abort(404)
    return send_file(pdf_path, as_attachment=True,
                     download_name=os.path.basename(pdf_path),
                     mimetype="application/pdf")


@app.route("/compare/<int:id1>/<int:id2>")
def compare_scans(id1, id2):
    scan1 = get_scan(id1)
    scan2 = get_scan(id2)
    if not scan1 or not scan2:
        abort(404)

    for s in (scan1, scan2):
        s["findings"]     = json.loads(s["findings"])
        s["compliance"]   = json.loads(s["compliance"])
        s["threat_intel"] = json.loads(s["threat_intel"])

    ports1 = {f["port"]: f for f in scan1["findings"]}
    ports2 = {f["port"]: f for f in scan2["findings"]}

    closed_ports  = [ports1[p] for p in ports1 if p not in ports2]
    new_ports     = [ports2[p] for p in ports2 if p not in ports1]
    changed_ports = []
    for p in ports1:
        if p in ports2:
            r1, r2 = ports1[p]["risk"], ports2[p]["risk"]
            if r1 != r2:
                changed_ports.append({
                    "port":      p,
                    "service":   ports1[p]["service"],
                    "old_risk":  r1,
                    "new_risk":  r2,
                    "direction": "escalated" if RISK_ORDER.get(r2, 0) > RISK_ORDER.get(r1, 0) else "improved",
                })

    return render_template(
        "compare.html",
        scan1=scan1, scan2=scan2,
        closed_ports=closed_ports,
        new_ports=new_ports,
        changed_ports=changed_ports,
    )


@app.route("/api/scans")
def api_scans():
    return jsonify(get_all_scans())


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
