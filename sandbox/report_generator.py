"""
report_generator.py
Generates a clean PDF incident report from timeline data.
Uses fpdf2 — pure Python, no external tools needed.
"""

from fpdf import FPDF
from datetime import datetime
import os



def _safe(text):
    """Strip non-latin-1 characters for fpdf compatibility."""
    return text.encode('latin-1', errors='replace').decode('latin-1')

class IncidentReport(FPDF):
    def header(self):
        self.set_fill_color(15, 17, 26)
        self.rect(0, 0, 210, 20, 'F')
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 6)
        self.cell(0, 8, "THREAT SIMULATION SANDBOX - INCIDENT REPORT", ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(6)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Page {self.page_no()}", align="C")


STATUS_COLORS = {
    "safe":       (16, 185, 129),
    "suspicious": (245, 158, 11),
    "attack":     (239, 68, 68),
    "response":   (139, 92, 246),
}


def generate_pdf(data: dict, output_dir: str = "reports") -> str:
    import json
    # Sanitize all text in data to latin-1 compatible chars
    raw = json.dumps(data).replace("—", "-").replace("–", "-").replace("‘", "'").replace("’", "'").replace("“", '"').replace("”", '"')
    data = json.loads(raw)
    os.makedirs(output_dir, exist_ok=True)

    scenario  = data.get("scenario", "unknown").replace("_", " ").title()
    timeline  = data.get("timeline", [])
    summary   = data.get("summary", {})
    compare   = data.get("compare", {})
    ai_text   = data.get("ai_explanation", "")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(output_dir, f"incident_{timestamp}.pdf")

    pdf = IncidentReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Title block ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(15, 17, 26)
    pdf.cell(0, 10, _safe(scenario), ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, _safe(f"Simulated on {datetime.now().strftime('%B %d, %Y at %H:%M')}"), ln=True)
    pdf.ln(4)

    # ── Summary grid ─────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 17, 26)
    pdf.cell(0, 8, _safe("Summary"), ln=True)
    pdf.ln(2)

    cols = [
        ("Total Events",     str(summary.get("total_events", 0))),
        ("Attacks Detected", str(summary.get("attacks_detected", 0))),
        ("Suspicious",       str(summary.get("suspicious_events", 0))),
        ("Threat Level",     summary.get("threat_level", "-")),
        ("Unique IPs",       str(summary.get("unique_ips", 0))),
        ("Responses",        str(summary.get("responses_taken", 0))),
    ]
    col_w = 31
    for i, (lbl, val) in enumerate(cols):
        x = 10 + (i % 6) * col_w
        if i % 6 == 0 and i > 0:
            pdf.ln(18)
        pdf.set_xy(x, pdf.get_y())
        pdf.set_fill_color(245, 245, 250)
        pdf.rect(x, pdf.get_y(), col_w - 2, 16, 'F')
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(120, 120, 120)
        pdf.set_xy(x + 2, pdf.get_y() + 2)
        pdf.cell(col_w - 4, 4, lbl.upper(), ln=False)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(15, 17, 26)
        pdf.set_xy(x + 2, pdf.get_y() + 4)
        pdf.cell(col_w - 4, 6, _safe(val), ln=False)

    pdf.ln(22)

    # ── Event timeline ────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 17, 26)
    pdf.cell(0, 8, _safe("Event Timeline"), ln=True)
    pdf.ln(2)

    for ev in timeline:
        status = ev.get("status", "safe")
        r, g, b = STATUS_COLORS.get(status, (200, 200, 200))
        x, y = pdf.get_x(), pdf.get_y()

        # Colored left bar
        pdf.set_fill_color(r, g, b)
        pdf.rect(10, y, 3, 10, 'F')

        # Row background
        pdf.set_fill_color(250, 250, 252)
        pdf.rect(14, y, 182, 10, 'F')

        # Timestamp
        pdf.set_xy(15, y + 1)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(18, 4, _safe(ev.get("timestamp", "")), ln=False)

        # Status badge
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(r, g, b)
        pdf.cell(20, 4, status.upper(), ln=False)

        # Detail
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, _safe(ev.get("detail", "")[:85]), ln=True)

        # Explanation (small, muted)
        pdf.set_xy(33, pdf.get_y() - 4)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(130, 130, 130)
        explain = ev.get("explanation", "")[:100]
        pdf.cell(0, 4, _safe(explain), ln=True)
        pdf.ln(1)

    # ── Compare section ────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 17, 26)
    pdf.cell(0, 8, _safe("Without Response vs. With Response"), ln=True)
    pdf.ln(2)

    half = 91
    y = pdf.get_y()

    pdf.set_fill_color(254, 242, 242)
    pdf.rect(10, y, half, 24, 'F')
    pdf.set_xy(12, y + 2)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(185, 28, 28)
    pdf.cell(0, 5, _safe("WITHOUT RESPONSE (no action taken)"), ln=True)
    pdf.set_xy(12, pdf.get_y())
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(half - 4, 4, _safe(compare.get("without", "-")))

    pdf.set_xy(10 + half + 4, y)
    pdf.set_fill_color(240, 253, 244)
    pdf.rect(10 + half + 4, y, half, 24, 'F')
    pdf.set_xy(12 + half + 4, y + 2)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(21, 128, 61)
    pdf.cell(0, 5, _safe("WITH RESPONSE (defended)"), ln=True)
    pdf.set_xy(12 + half + 4, pdf.get_y())
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(half - 4, 4, _safe(compare.get("with", "-")))

    pdf.ln(30)

    # ── AI explanation ─────────────────────────────────────────────────────────
    if ai_text:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(15, 17, 26)
        pdf.cell(0, 8, _safe("AI Security Analysis"), ln=True)
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, _safe(ai_text))

    pdf.output(filename)
    return filename
