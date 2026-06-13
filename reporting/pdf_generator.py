import os
import io
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak, Image,
                                 KeepTogether)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ml.predictor import get_model_metrics

# ── PDF colour palette (light theme — fully readable) ──────────────────────
NAVY        = colors.HexColor("#0F2144")
BLUE        = colors.HexColor("#1D4ED8")
BLUE_LIGHT  = colors.HexColor("#EFF6FF")
SLATE       = colors.HexColor("#334155")
MUTED       = colors.HexColor("#64748B")
BORDER      = colors.HexColor("#CBD5E1")
PAGE_BG     = colors.white
ROW_ALT     = colors.HexColor("#F8FAFC")

C_CRITICAL  = colors.HexColor("#DC2626")
C_HIGH      = colors.HexColor("#EA580C")
C_MEDIUM    = colors.HexColor("#D97706")
C_LOW       = colors.HexColor("#16A34A")
C_PASS      = colors.HexColor("#15803D")
C_FAIL      = colors.HexColor("#B91C1C")

RISK_PALETTE = {"CRITICAL": "#DC2626", "HIGH": "#EA580C",
                "MEDIUM":   "#D97706", "LOW":  "#16A34A"}


# ── Matplotlib helpers ─────────────────────────────────────────────────────

def _fig_to_image(fig, width_cm=8):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=width_cm * cm)


def _risk_pie(results):
    counts = {k: 0 for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for r in results:
        counts[r.get("risk", "LOW")] += 1
    active = {k: v for k, v in counts.items() if v > 0}
    if not active:
        return None

    fig, ax = plt.subplots(figsize=(4, 3.2), facecolor='white')
    ax.set_facecolor('white')
    wedge_colors = [RISK_PALETTE[k] for k in active]
    wedges, texts, autotexts = ax.pie(
        list(active.values()), labels=None,
        colors=wedge_colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.75,
        wedgeprops=dict(linewidth=1.5, edgecolor='white')
    )
    for at in autotexts:
        at.set_color('white'); at.set_fontsize(8); at.set_fontweight('bold')
    patches = [mpatches.Patch(color=RISK_PALETTE[k], label=f"{k}  ({v})")
               for k, v in active.items()]
    ax.legend(handles=patches, loc='lower center', bbox_to_anchor=(0.5, -0.18),
              ncol=2, frameon=False, fontsize=7)
    ax.set_title("Risk Distribution", fontsize=9, fontweight='bold', color='#0F2144', pad=6)
    return _fig_to_image(fig, width_cm=7)


def _score_gauge(score):
    fig, ax = plt.subplots(figsize=(3.5, 2.5), subplot_kw=dict(polar=False), facecolor='white')
    ax.set_facecolor('white')
    ax.set_xlim(0, 10); ax.set_ylim(0, 10)
    ax.axis('off')

    colour = "#DC2626" if score >= 70 else "#D97706" if score >= 40 else "#16A34A"
    theta  = np.linspace(np.pi, 0, 200)
    r      = 3.5
    cx, cy = 5, 3
    ax.plot(cx + r * np.cos(theta), cy + r * np.sin(theta), lw=8,
            color='#E2E8F0', solid_capstyle='round')
    frac  = score / 100
    theta2 = np.linspace(np.pi, np.pi - frac * np.pi, 200)
    ax.plot(cx + r * np.cos(theta2), cy + r * np.sin(theta2), lw=8,
            color=colour, solid_capstyle='round')
    ax.text(cx, cy - 0.2, str(score), ha='center', va='center',
            fontsize=28, fontweight='bold', color=colour)
    ax.text(cx, cy - 1.3, '/ 100', ha='center', va='center',
            fontsize=9, color='#64748B')
    label = "HIGH RISK" if score >= 70 else "MODERATE" if score >= 40 else "LOW RISK"
    ax.text(cx, 0.8, label, ha='center', va='center',
            fontsize=8, fontweight='bold', color=colour)
    return _fig_to_image(fig, width_cm=6)


def _port_bar(results):
    if not results:
        return None
    ports   = [str(r["port"]) for r in results[:12]]
    risks   = [r.get("risk", "LOW") for r in results[:12]]
    colours = [RISK_PALETTE[r] for r in risks]

    fig, ax = plt.subplots(figsize=(8, 2.8), facecolor='white')
    ax.set_facecolor('#F8FAFC')
    y = range(len(ports))
    bars = ax.barh(list(y), [1] * len(ports), color=colours,
                   edgecolor='white', linewidth=0.5, height=0.6)
    ax.set_yticks(list(y))
    ax.set_yticklabels([f":{p}" for p in ports], fontsize=7.5,
                        fontfamily='monospace', color='#334155')
    ax.set_xticks([]); ax.set_xlim(0, 1.4)
    for i, (bar, risk) in enumerate(zip(bars, risks)):
        ax.text(1.05, bar.get_y() + bar.get_height() / 2,
                risk, va='center', fontsize=7, fontweight='bold',
                color=RISK_PALETTE[risk])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['left'].set_color('#CBD5E1')
    ax.set_title("Port Risk Overview", fontsize=9, fontweight='bold',
                 color='#0F2144', loc='left', pad=8)
    ax.invert_yaxis()
    return _fig_to_image(fig, width_cm=13)


def _shap_bar(shap_contributions, title="SHAP Feature Contributions"):
    if not shap_contributions:
        return None
    top = shap_contributions[:6]
    names  = [c["feature"] for c in top]
    values = [c["shap_value"] for c in top]
    colors_bar = ["#DC2626" if v > 0 else "#16A34A" for v in values]

    fig, ax = plt.subplots(figsize=(7, 2.4), facecolor='white')
    ax.set_facecolor('#F8FAFC')
    y = range(len(names))
    ax.barh(list(y), values, color=colors_bar, edgecolor='white', linewidth=0.5, height=0.55)
    ax.axvline(0, color='#CBD5E1', linewidth=0.8)
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=7, color='#334155')
    ax.set_xlabel("SHAP value (positive = increases risk)", fontsize=6.5, color='#64748B')
    ax.tick_params(axis='x', labelsize=6.5, colors='#64748B')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#CBD5E1')
    ax.spines['bottom'].set_color('#CBD5E1')
    ax.set_title(title, fontsize=8, fontweight='bold', color='#0F2144', loc='left', pad=6)
    ax.invert_yaxis()
    return _fig_to_image(fig, width_cm=10)


def _confusion_matrix_img(cm_data, class_labels):
    if not cm_data:
        return None
    cm_arr = np.array(cm_data)
    fig, ax = plt.subplots(figsize=(4, 3.2), facecolor='white')
    ax.set_facecolor('white')
    im = ax.imshow(cm_arr, interpolation='nearest', cmap='Blues')
    ax.set_xticks(range(len(class_labels)))
    ax.set_yticks(range(len(class_labels)))
    ax.set_xticklabels(class_labels, fontsize=7, rotation=30, ha='right', color='#334155')
    ax.set_yticklabels(class_labels, fontsize=7, color='#334155')
    ax.set_xlabel("Predicted", fontsize=7.5, color='#334155')
    ax.set_ylabel("Actual", fontsize=7.5, color='#334155')
    ax.set_title("Confusion Matrix", fontsize=9, fontweight='bold', color='#0F2144', pad=6)
    thresh = cm_arr.max() / 2.0
    for i in range(cm_arr.shape[0]):
        for j in range(cm_arr.shape[1]):
            ax.text(j, i, str(cm_arr[i, j]), ha='center', va='center',
                    fontsize=9, fontweight='bold',
                    color='white' if cm_arr[i, j] > thresh else '#0F2144')
    fig.tight_layout()
    return _fig_to_image(fig, width_cm=7)


def _compliance_bar(compliance):
    total     = 10
    passed    = len(compliance.get("compliant_controls", []))
    failed    = total - passed
    score     = compliance.get("compliance_score", 0)
    colour    = "#16A34A" if score >= 70 else "#D97706" if score >= 40 else "#DC2626"

    fig, ax = plt.subplots(figsize=(7, 1.2), facecolor='white')
    ax.set_facecolor('white')
    ax.barh([0], [passed], color="#16A34A", height=0.4, label=f"Pass ({passed})")
    ax.barh([0], [failed], left=[passed], color="#DC2626", height=0.4, label=f"Fail ({failed})")
    ax.set_xlim(0, 10); ax.set_yticks([]); ax.set_xticks(range(11))
    ax.set_xticklabels([str(i) for i in range(11)], fontsize=7, color='#64748B')
    ax.legend(loc='upper right', fontsize=7, frameon=False)
    ax.spines[:].set_visible(False)
    ax.set_title(f"OWASP Controls: {passed}/10 Passed  ({score}% compliant)",
                 fontsize=8, fontweight='bold', color='#0F2144', loc='left')
    return _fig_to_image(fig, width_cm=13)


# ── ReportLab style helpers ─────────────────────────────────────────────────

def _styles():
    return {
        "h1":     ParagraphStyle("h1",  fontName="Helvetica-Bold", fontSize=24,
                                  textColor=NAVY, spaceAfter=4, alignment=TA_LEFT),
        "h2":     ParagraphStyle("h2",  fontName="Helvetica-Bold", fontSize=13,
                                  textColor=NAVY, spaceBefore=10, spaceAfter=4),
        "h3":     ParagraphStyle("h3",  fontName="Helvetica-Bold", fontSize=10,
                                  textColor=SLATE, spaceBefore=6, spaceAfter=3),
        "body":   ParagraphStyle("body",fontName="Helvetica", fontSize=9,
                                  textColor=SLATE, spaceAfter=4, leading=14),
        "small":  ParagraphStyle("small",fontName="Helvetica", fontSize=8,
                                  textColor=MUTED, spaceAfter=2, leading=11),
        "center": ParagraphStyle("center",fontName="Helvetica", fontSize=9,
                                  textColor=SLATE, alignment=TA_CENTER),
        "mono":   ParagraphStyle("mono", fontName="Courier", fontSize=8,
                                  textColor=SLATE),
        "cover_title": ParagraphStyle("ct", fontName="Helvetica-Bold", fontSize=32,
                                       textColor=PAGE_BG, alignment=TA_LEFT),
        "cover_sub":   ParagraphStyle("cs", fontName="Helvetica", fontSize=13,
                                       textColor=colors.HexColor("#93C5FD"), alignment=TA_LEFT),
        "cover_meta":  ParagraphStyle("cm", fontName="Helvetica", fontSize=10,
                                       textColor=colors.HexColor("#CBD5E1"), alignment=TA_LEFT),
        "footer": ParagraphStyle("footer", fontName="Helvetica", fontSize=7,
                                  textColor=MUTED, alignment=TA_CENTER),
    }


def _tbl(data, col_widths, header_bg=NAVY, zebra=True):
    style = [
        ("BACKGROUND",    (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  PAGE_BG),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  8.5),
        ("TOPPADDING",    (0, 0), (-1, 0),  7),
        ("BOTTOMPADDING", (0, 0), (-1, 0),  7),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("TOPPADDING",    (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",     (0, 1), (-1, -1), SLATE),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    if zebra:
        for i in range(1, len(data), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def _risk_para(risk, style):
    color_map = {"CRITICAL": "#DC2626", "HIGH": "#EA580C",
                 "MEDIUM": "#D97706", "LOW": "#16A34A"}
    c = color_map.get(risk, "#64748B")
    return Paragraph(f'<font color="{c}"><b>{risk}</b></font>', style)


def _section_header(text, s):
    return [
        Paragraph(text, s["h2"]),
        HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=6),
    ]


# ── Main generator ──────────────────────────────────────────────────────────

def generate_pdf(display_name, ip, results, score, compliance, threat_intel,
                 output_dir=".") -> str:
    ts       = datetime.now()
    filename = os.path.join(output_dir,
                            f"INVA_Report_{ip}_{ts.strftime('%Y%m%d_%H%M%S')}.pdf")

    doc = SimpleDocTemplate(
        filename, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm, bottomMargin=1.8*cm,
        title=f"INVA Vulnerability Report — {display_name}",
    )

    s     = _styles()
    story = []
    W     = A4[0] - 3.6*cm   # usable width

    # ── COVER ────────────────────────────────────────────────────────────────
    cover_bg = Table(
        [[
            Paragraph("INVA", ParagraphStyle("logo", fontName="Helvetica-Bold",
                                              fontSize=11, textColor=colors.HexColor("#38BDF8"))),
            Paragraph("INTELLIGENT NETWORK VULNERABILITY ANALYSER",
                      ParagraphStyle("logoSub", fontName="Helvetica", fontSize=8,
                                     textColor=colors.HexColor("#93C5FD"))),
        ]],
        colWidths=[2*cm, W - 2*cm]
    )
    cover_bg.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING",(0, 0), (-1, -1), 12),
    ]))
    story.append(cover_bg)
    story.append(Spacer(1, 1.5*cm))

    verdict      = "HIGH RISK" if score >= 70 else "MODERATE RISK" if score >= 40 else "LOW RISK"
    verdict_col  = colors.HexColor("#DC2626") if score >= 70 else \
                   colors.HexColor("#D97706") if score >= 40 else \
                   colors.HexColor("#16A34A")

    story.append(Paragraph("Vulnerability Assessment Report", s["h1"]))
    story.append(Spacer(1, 0.4*cm))

    meta_rows = [
        ["Target",        display_name],
        ["Resolved IP",   ip],
        ["Scan Date",     ts.strftime("%d %B %Y, %H:%M UTC")],
        ["Threat Rep.",   threat_intel.get("reputation", "N/A")],
        ["Compliance",    f"{compliance.get('compliance_score', 0)}/100"],
    ]
    meta_tbl = Table(meta_rows, colWidths=[3.5*cm, W - 3.5*cm])
    meta_tbl.setStyle(TableStyle([
        ("TEXTCOLOR",     (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR",     (1, 0), (1, -1), SLATE),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), ROW_ALT),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.8*cm))

    # Score gauge + risk pie side by side
    gauge = _score_gauge(score)
    pie   = _risk_pie(results)
    if gauge and pie:
        vis_tbl = Table([[gauge, pie]], colWidths=[7*cm, W - 7*cm])
        vis_tbl.setStyle(TableStyle([
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING",  (0,0),(-1,-1), 0),
            ("RIGHTPADDING", (0,0),(-1,-1), 0),
        ]))
        story.append(vis_tbl)
    elif gauge:
        story.append(gauge)

    story.append(Spacer(1, 0.6*cm))
    story.append(Paragraph(
        f"Overall verdict: <font color=\"{'#DC2626' if score>=70 else '#D97706' if score>=40 else '#16A34A'}\"><b>{verdict}</b></font> — "
        f"risk score <b>{score}/100</b> across <b>{len(results)}</b> open port(s).",
        s["body"]
    ))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────
    story.extend(_section_header("Executive Summary", s))

    high_c = sum(1 for r in results if r.get("risk") in ("HIGH", "CRITICAL"))
    med_c  = sum(1 for r in results if r.get("risk") == "MEDIUM")
    low_c  = sum(1 for r in results if r.get("risk") == "LOW")
    geo    = threat_intel.get("geolocation", {})

    summary = (
        f"This report presents the findings of an automated intelligence-driven vulnerability assessment "
        f"conducted against <b>{display_name}</b> (resolved IP: <b>{ip}</b>). "
        f"The target is hosted in <b>{geo.get('city','N/A')}, {geo.get('country','N/A')}</b> "
        f"({geo.get('isp','N/A')}). "
        f"A total of <b>{len(results)}</b> open ports were identified. "
        f"The AI/ML engine classified <b>{high_c}</b> as high/critical, "
        f"<b>{med_c}</b> as medium, and <b>{low_c}</b> as low severity. "
        f"The IP reputation is rated <b>{threat_intel.get('reputation','N/A')}</b> "
        f"with a threat intelligence score of <b>{threat_intel.get('threat_score',0)}/100</b>. "
        f"OWASP Top 10 compliance stands at <b>{compliance.get('compliance_score',0)}%</b> "
        f"with <b>{len(compliance.get('violations',{}))}</b> control violation(s) detected."
    )
    story.append(Paragraph(summary, s["body"]))
    story.append(Spacer(1, 0.5*cm))

    summary_data = [
        ["Metric", "Value", "Severity"],
        ["Open Ports Discovered", str(len(results)), "—"],
        ["High / Critical Findings", str(high_c),
         "CRITICAL" if high_c >= 3 else "HIGH" if high_c >= 1 else "LOW"],
        ["Medium Findings",  str(med_c),  "MEDIUM" if med_c >= 1 else "LOW"],
        ["Low Findings",     str(low_c),  "LOW"],
        ["Risk Score",       f"{score}/100",
         "CRITICAL" if score >= 70 else "HIGH" if score >= 55 else "MEDIUM" if score >= 30 else "LOW"],
        ["Threat Reputation", threat_intel.get("reputation","N/A"),
         "HIGH" if threat_intel.get("reputation") in ("MALICIOUS","SUSPICIOUS") else "LOW"],
        ["OWASP Compliance", f"{compliance.get('compliance_score',0)}%",
         "LOW" if compliance.get('compliance_score',0) >= 70 else "MEDIUM"],
    ]
    rows = []
    for i, row in enumerate(summary_data):
        if i == 0:
            rows.append(row)
        else:
            rows.append([row[0], row[1], _risk_para(row[2], s["center"])])
    story.append(_tbl(rows, [8*cm, 5*cm, W - 13*cm]))

    port_chart = _port_bar(results)
    if port_chart:
        story.append(Spacer(1, 0.6*cm))
        story.append(port_chart)

    story.append(PageBreak())

    # ── TECHNICAL FINDINGS ───────────────────────────────────────────────────
    story.extend(_section_header("Technical Findings", s))
    story.append(Paragraph(
        "Each open port is analysed by a rule-based CVE engine and an AI/ML Random Forest "
        "classifier (200 trees, 8 engineered features). The higher of the two risk ratings is "
        "used as the final verdict. CVSS scores are derived from the NIST NVD severity scale.",
        s["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    rows = [["Port", "Service", "Rule Risk", "ML Risk", "Conf.", "CVSS", "Issue / CVE", "Remediation"]]
    for r in results:
        ml   = r.get("ml_prediction", {}) or {}
        cvss = r.get("cvss_score", "—")
        fix  = str(r.get("fix", ""))
        fix  = fix[:50] + "…" if len(fix) > 50 else fix
        iss  = str(r.get("issue", ""))
        iss  = iss[:32] + "…" if len(iss) > 32 else iss
        rows.append([
            Paragraph(f"<b>{r['port']}</b>", s["mono"]),
            r.get("service", ""),
            _risk_para(r.get("risk", "LOW"), s["center"]),
            _risk_para(ml.get("predicted_risk", "—"), s["center"]),
            f"{ml.get('confidence', 0)}%" if ml else "—",
            str(cvss),
            Paragraph(iss, s["small"]),
            Paragraph(fix, s["small"]),
        ])
    story.append(_tbl(rows, [1.5*cm, 2.3*cm, 2*cm, 2*cm, 1.5*cm, 1.5*cm, 4*cm, W-14.8*cm]))
    story.append(PageBreak())

    # ── ML INTELLIGENCE ─────────────────────────────────────────────────────
    story.extend(_section_header("ML Model Intelligence & Explainability", s))

    metrics = get_model_metrics()
    if metrics:
        story.append(Paragraph(
            f"The risk classifier is a <b>Random Forest</b> ensemble of "
            f"<b>{metrics.get('n_estimators', 200)} decision trees</b> trained on "
            f"<b>{metrics.get('n_training_samples', 'N/A')} samples</b> across "
            f"<b>{metrics.get('n_features', 8)} security-domain features</b>. "
            f"It achieved <b>{metrics.get('test_accuracy', 'N/A')}% hold-out accuracy</b> and "
            f"<b>{metrics.get('cv_accuracy', 'N/A')}% ± {metrics.get('cv_std', 'N/A')}% "
            f"5-fold cross-validation accuracy</b>, demonstrating robust generalisation "
            f"across unseen port/service combinations.",
            s["body"]
        ))
        story.append(Spacer(1, 0.4*cm))

        # Model metrics summary table
        cr = metrics.get("classification_report", {})
        met_rows = [["Risk Class", "Precision", "Recall", "F1-Score", "Support"]]
        for cls in metrics.get("classes", []):
            cls_stats = cr.get(cls, {})
            met_rows.append([
                cls,
                f"{cls_stats.get('precision', 0):.2f}",
                f"{cls_stats.get('recall', 0):.2f}",
                f"{cls_stats.get('f1-score', 0):.2f}",
                str(int(cls_stats.get('support', 0))),
            ])
        overall = cr.get("weighted avg", {})
        met_rows.append([
            "Weighted Avg",
            f"{overall.get('precision', 0):.2f}",
            f"{overall.get('recall', 0):.2f}",
            f"{overall.get('f1-score', 0):.2f}",
            str(int(overall.get('support', 0))),
        ])
        story.append(_tbl(met_rows, [4*cm, 3*cm, 3*cm, 3*cm, W-13*cm]))
        story.append(Spacer(1, 0.4*cm))

        # Confusion matrix + feature importances side by side
        cm_img = _confusion_matrix_img(
            metrics.get("confusion_matrix"), metrics.get("classes", [])
        )
        fi = metrics.get("feature_importances", [])
        fn = metrics.get("feature_names", [])
        if fi and fn and cm_img:
            # Feature importance bar chart
            fig_fi, ax_fi = plt.subplots(figsize=(4.5, 3.2), facecolor='white')
            ax_fi.set_facecolor('#F8FAFC')
            y_fi = range(len(fn))
            ax_fi.barh(list(y_fi), fi, color='#1D4ED8', edgecolor='white',
                       linewidth=0.5, height=0.55)
            ax_fi.set_yticks(list(y_fi))
            ax_fi.set_yticklabels(fn, fontsize=6.5, color='#334155')
            ax_fi.set_xlabel("Importance", fontsize=6.5, color='#64748B')
            ax_fi.tick_params(axis='x', labelsize=6.5, colors='#64748B')
            ax_fi.spines['top'].set_visible(False)
            ax_fi.spines['right'].set_visible(False)
            ax_fi.set_title("Feature Importances", fontsize=8, fontweight='bold',
                             color='#0F2144', loc='left', pad=6)
            ax_fi.invert_yaxis()
            fi_img = _fig_to_image(fig_fi, width_cm=7)

            side = Table([[cm_img, fi_img]], colWidths=[8*cm, W-8*cm])
            side.setStyle(TableStyle([
                ("VALIGN",  (0, 0), (-1, -1), "TOP"),
                ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))
            story.append(side)

    # SHAP explanations for top 3 highest-risk findings
    high_risk = sorted(
        [r for r in results if r.get("shap_explanation")],
        key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("risk"), 4)
    )[:3]

    if high_risk:
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("SHAP Explainability — Top Risk Findings", s["h3"]))
        story.append(Paragraph(
            "SHAP (SHapley Additive exPlanations) values show exactly which features drove "
            "the ML model's risk classification for each finding. "
            "Red bars increase predicted risk; green bars decrease it.",
            s["small"]
        ))
        story.append(Spacer(1, 0.3*cm))

        for r in high_risk:
            ml   = r.get("ml_prediction", {}) or {}
            shap = r.get("shap_explanation", [])
            title = (f"Port {r['port']} ({r.get('service','')})  —  "
                     f"ML: {ml.get('predicted_risk','?')}  "
                     f"({ml.get('confidence', 0)}% confidence)")
            img = _shap_bar(shap, title=title)
            if img:
                story.append(img)
                story.append(Spacer(1, 0.2*cm))

    story.append(PageBreak())

    # ── THREAT INTELLIGENCE ──────────────────────────────────────────────────
    story.extend(_section_header("Threat Intelligence Analysis", s))

    ti_rows = [
        ["Field", "Value"],
        ["Target",         display_name],
        ["Resolved IP",    ip],
        ["Threat Score",   f"{threat_intel.get('threat_score',0)} / 100"],
        ["Reputation",     threat_intel.get("reputation","N/A")],
        ["Country",        geo.get("country","Unknown")],
        ["City",           geo.get("city","Unknown")],
        ["ISP",            geo.get("isp","Unknown")],
        ["Organisation",   geo.get("org","Unknown")],
        ["ASN",            geo.get("asn","Unknown")],
        ["Hosting/DC",     "Yes" if geo.get("hosting") else "No"],
        ["Blacklist Hits", ", ".join(threat_intel.get("blacklist_hits",[])) or "None detected"],
    ]
    story.append(_tbl(ti_rows, [5*cm, W - 5*cm]))
    story.append(Spacer(1, 0.4*cm))

    if threat_intel.get("indicators"):
        story.append(Paragraph("Threat Indicators Detected:", s["h3"]))
        for ind in threat_intel["indicators"]:
            story.append(Paragraph(f"▸  {ind}", s["body"]))

    pt = threat_intel.get("port_threats", [])
    if pt:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("High-Risk Port Exposure:", s["h3"]))
        pt_rows = [["Port", "Service", "Severity", "Detail"]]
        for p in pt:
            pt_rows.append([
                Paragraph(f"<b>{p['port']}</b>", s["mono"]),
                p["service"],
                _risk_para(p["severity"], s["center"]),
                Paragraph(p["detail"], s["small"]),
            ])
        story.append(_tbl(pt_rows, [2*cm, 3.5*cm, 3*cm, W - 8.5*cm]))

    story.append(PageBreak())

    # ── OWASP COMPLIANCE ────────────────────────────────────────────────────
    story.extend(_section_header("OWASP Top 10 Compliance Mapping (2021)", s))

    comp_chart = _compliance_bar(compliance)
    if comp_chart:
        story.append(comp_chart)
        story.append(Spacer(1, 0.4*cm))

    owasp_labels = compliance.get("owasp_labels", {})
    violations   = compliance.get("violations", {})

    comp_rows = [["ID", "Control", "Status", "Violations"]]
    for oid, label in owasp_labels.items():
        if oid in violations:
            status = Paragraph('<font color="#B91C1C"><b>FAIL</b></font>', s["center"])
            detail_text = "; ".join(
                f"Port {f['port']}" for f in violations[oid]["findings"]
            )[:60]
        else:
            status = Paragraph('<font color="#15803D"><b>PASS</b></font>', s["center"])
            detail_text = "No violations"
        comp_rows.append([oid, label, status, detail_text])

    story.append(_tbl(comp_rows, [1.5*cm, 8.5*cm, 2.5*cm, W - 12.5*cm]))

    if violations:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Violation Details:", s["h3"]))
        for oid, vdata in violations.items():
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(f"<b>{oid} — {vdata['title']}</b>", s["body"]))
            for f in vdata["findings"][:3]:
                story.append(Paragraph(f"  ▸  Port {f['port']} ({f['service']}): {f['detail'][:90]}", s["small"]))

    story.append(PageBreak())

    # ── REMEDIATION ─────────────────────────────────────────────────────────
    story.extend(_section_header("Remediation Recommendations", s))
    story.append(Paragraph(
        "Recommendations are prioritised by severity. Address CRITICAL and HIGH items immediately.",
        s["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    recs = sorted(
        [(r.get("risk","LOW"), r.get("port"), r.get("service",""), r.get("fix",""))
         for r in results if r.get("fix","") not in ("Monitor","N/A","")],
        key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x[0],4)
    )
    if recs:
        rec_rows = [["Priority", "Port", "Service", "Recommended Action"]]
        for risk, port, svc, fix in recs:
            rec_rows.append([
                _risk_para(risk, s["center"]),
                Paragraph(f"<b>{port}</b>", s["mono"]),
                svc,
                Paragraph(fix[:100], s["small"]),
            ])
        story.append(_tbl(rec_rows, [2.5*cm, 2*cm, 3*cm, W - 7.5*cm]))
    else:
        story.append(Paragraph("No specific remediation items identified.", s["body"]))

    # ── FOOTER ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.15*cm))
    story.append(Paragraph(
        f"INVA — Intelligent Network Vulnerability Analyser  ·  "
        f"Report generated {ts.strftime('%d %B %Y at %H:%M UTC')}  ·  "
        f"For authorised security assessment use only.",
        s["footer"]
    ))

    doc.build(story)
    return filename
