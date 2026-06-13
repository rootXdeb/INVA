import socket
import os
from urllib.parse import urlparse

from scanner.port_scanner import scan_ports
from scanner.service_detector import detect_service
from analyzer.vulnerability_engine import analyze_with_ml
from scoring.risk_score import calculate_score
from reporting.report_generator import save_report
from reporting.pdf_generator import generate_pdf
from threat_intel.intel_engine import analyze_ip
from compliance.mapper import map_findings
from database.db import save_scan


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except socket.error:
        return False


def resolve_target(target: str) -> tuple:
    """Returns (ip, display_name). Accepts IP, hostname, or full URL."""
    target = target.strip()

    if '://' in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or target
    else:
        hostname = target.split('/')[0]

    if _is_ip(hostname):
        return hostname, target

    try:
        ip = socket.gethostbyname(hostname)
        return ip, target
    except socket.gaierror:
        raise ValueError(f"Cannot resolve '{hostname}'. Check the address and try again.")


def run_scan(target: str, progress_cb=None) -> dict:
    def _progress(msg):
        if progress_cb:
            progress_cb(msg)

    _progress("Resolving target...")
    ip, display_name = resolve_target(target)
    _progress(f"Resolved → {ip}")

    _progress("Scanning ports (20–1024)...")
    ports = scan_ports(ip)
    _progress(f"Found {len(ports)} open port(s)")

    results = []
    total = len(ports)
    for i, port in enumerate(ports, 1):
        _progress(f"Analysing port {port} ({i}/{total})...")
        service, banner = detect_service(ip, port)
        analysis = analyze_with_ml(port, service, banner)
        results.append({
            "port": port,
            "service": service,
            "banner": (banner or "")[:120],
            "risk": analysis["risk"],
            "issue": analysis["issue"],
            "fix": analysis["fix"],
            "ml_prediction": analysis["ml_prediction"],
        })

    _progress("Calculating risk score...")
    score = calculate_score(results)

    _progress("Running threat intelligence analysis...")
    threat_intel = analyze_ip(ip, [r["port"] for r in results])

    _progress("Mapping OWASP compliance controls...")
    compliance = map_findings(results)

    _progress("Generating PDF report...")
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    json_report = save_report(ip, results, score)
    pdf_report  = generate_pdf(display_name, ip, results, score, compliance, threat_intel,
                               output_dir=reports_dir)

    scan_id = save_scan(display_name, score, results, compliance, threat_intel,
                        json_report, pdf_report)

    _progress("Scan complete.")
    return {
        "scan_id":     scan_id,
        "target":      display_name,
        "ip":          ip,
        "results":     results,
        "score":       score,
        "threat_intel": threat_intel,
        "compliance":  compliance,
        "json_report": json_report,
        "pdf_report":  pdf_report,
    }
