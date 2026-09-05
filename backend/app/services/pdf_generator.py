import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.core.config import settings

class SecurityReportPDFGenerator:

    @staticmethod
    def generate_pdf(report_data: dict, output_path: str) -> str:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom cybersecurity dark/blue color scheme
        DARK_NAVY = colors.HexColor("#0f172a")
        ACCENT_CYAN = colors.HexColor("#06b6d4")
        ACCENT_RED = colors.HexColor("#ef4444")
        TEXT_MUTED = colors.HexColor("#64748b")
        BG_LIGHT = colors.HexColor("#f8fafc")
        BORDER_COLOR = colors.HexColor("#e2e8f0")

        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=DARK_NAVY
        )
        
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=TEXT_MUTED
        )

        h1_style = ParagraphStyle(
            'H1Heading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=DARK_NAVY,
            spaceBefore=14,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )

        code_style = ParagraphStyle(
            'CodeSnippet',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a")
        )

        elements = []

        # 1. Header Banner
        repo_name = report_data.get("repository_name", "Repository")
        gen_time = report_data.get("generated_at", "N/A")
        
        elements.append(Paragraph("SecureCodeOps AI", ParagraphStyle('Brand', fontName='Helvetica-Bold', fontSize=12, textColor=ACCENT_CYAN)))
        elements.append(Paragraph(f"Security Assessment Report: {repo_name}", title_style))
        elements.append(Paragraph(f"Multi-Agent Automated DevSecOps Audit &bull; Generated: {gen_time}", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT_CYAN, spaceBefore=4, spaceAfter=14))

        # 2. Executive Summary
        elements.append(Paragraph("1. Executive Summary", h1_style))
        exec_summary = report_data.get("executive_summary", "")
        elements.append(Paragraph(exec_summary, body_style))
        elements.append(Spacer(1, 12))

        # 3. Security Score & Metrics Summary Table
        metrics = report_data.get("summary_metrics", {})
        score_data = report_data.get("security_score_breakdown", {})
        score = score_data.get("security_score", 100.0)

        score_table_data = [
            [
                Paragraph(f"<b>Overall Security Score</b><br/><font size=16 color='{DARK_NAVY.hexval()}'><b>{score}/100</b></font>", body_style),
                Paragraph(f"<b>Compliance Score</b><br/><font size=16 color='{ACCENT_CYAN.hexval()}'><b>{metrics.get('compliance_score', 100)}%</b></font>", body_style),
                Paragraph(f"<b>Total Vulnerabilities</b><br/><font size=16 color='{ACCENT_RED.hexval()}'><b>{metrics.get('total_vulnerabilities', 0)}</b></font>", body_style),
                Paragraph(f"<b>STRIDE Threats</b><br/><font size=16 color='{DARK_NAVY.hexval()}'><b>{metrics.get('stride_threats', 0)}</b></font>", body_style),
            ]
        ]
        
        t_summary = Table(score_table_data, colWidths=[130, 130, 130, 130])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 14))

        # 4. Detailed Vulnerability Findings
        elements.append(Paragraph("2. Critical & High Security Findings", h1_style))
        findings = report_data.get("findings", [])
        
        if not findings:
            elements.append(Paragraph("No vulnerabilities detected in this scan.", body_style))
        else:
            findings_table_data = [["Severity", "Title", "CWE / OWASP", "Location", "Scanner"]]
            for f in findings[:15]:  # Top findings
                sev = f.get("severity", "MEDIUM")
                findings_table_data.append([
                    Paragraph(f"<b>{sev}</b>", body_style),
                    Paragraph(f.get("title", ""), body_style),
                    Paragraph(f"{f.get('cwe', '')}<br/>{f.get('owasp', '')}", body_style),
                    Paragraph(f"{f.get('file_path', '')}:{f.get('line_number', 1)}", body_style),
                    Paragraph(f.get("scanner", ""), body_style)
                ])
            
            t_findings = Table(findings_table_data, colWidths=[65, 175, 110, 120, 50])
            t_findings.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t_findings)

        elements.append(Spacer(1, 14))

        # 5. STRIDE Threat Model Summary
        elements.append(Paragraph("3. STRIDE Threat Model Analysis", h1_style))
        threats = report_data.get("threats", [])
        if threats:
            threat_table_data = [["Category", "Threat Title", "Risk Level", "Impact x Prob", "Recommended Control"]]
            for t in threats[:8]:
                threat_table_data.append([
                    Paragraph(f"<b>{t.get('category')}</b>", body_style),
                    Paragraph(t.get("title", ""), body_style),
                    Paragraph(f"<b>{t.get('risk_level')}</b>", body_style),
                    Paragraph(f"{t.get('impact')} &times; {t.get('probability')} = {t.get('risk_score')}", body_style),
                    Paragraph((t.get("recommended_controls") or ["None"])[0], body_style)
                ])

            t_threats = Table(threat_table_data, colWidths=[90, 150, 60, 70, 150])
            t_threats.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t_threats)

        elements.append(Spacer(1, 14))

        # 6. Verified Patches
        elements.append(Paragraph("4. Context-Aware Patch Recommendations", h1_style))
        patches = report_data.get("patches", [])
        if patches:
            for p in patches[:3]:
                elements.append(Paragraph(f"<b>Patch for {p.get('file_path')}</b> &bull; Status: {p.get('status')} &bull; Re-scan Verified: {'Yes' if p.get('is_validated') else 'No'}", body_style))
                elements.append(Paragraph(f"<i>{p.get('explanation')}</i>", body_style))
                elements.append(Spacer(1, 4))
                diff_table = Table([[Paragraph(p.get("diff", "")[:400].replace("\n", "<br/>"), code_style)]], colWidths=[520])
                diff_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('PADDING', (0, 0), (-1, -1), 6)
                ]))
                elements.append(diff_table)
                elements.append(Spacer(1, 8))

        doc.build(elements)
        return output_path
