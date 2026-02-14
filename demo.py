#!/usr/bin/env python3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

SAMPLE_VULNERABILITIES = [
    {
        'id': 'CVE-2020-28493',
        'aliases': ['GHSA-g3rq-g295-4j3m', 'PYSEC-2021-66'],
        'modified': '2026-02-05T03:43:52.839085Z',
        'published': '2021-02-01T20:15:12.517Z',
        'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'}],
        'affected': [{
            'package': {'ecosystem': 'PyPI', 'name': 'jinja2'},
            'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.11.3'}]}],
            'versions': ['2.0', '2.1', '2.10', '2.10.1', '2.10.2', '2.10.3', '2.11.0', '2.11.1', '2.11.2']
        }],
        'summary': 'ReDoS vulnerability in jinja2 urlize filter',
        'details': 'This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the `_punctuation_re regex` operator and its use of multiple wildcards.',
        'database_specific': {'cwe_ids': ['CWE-400']},
        'references': [
            {'type': 'ADVISORY', 'url': 'https://snyk.io/vuln/SNYK-PYTHON-JINJA2-1012994'},
            {'type': 'FIX', 'url': 'https://github.com/pallets/jinja/pull/1343'}
        ]
    },
    {
        'id': 'CVE-2024-10491',
        'aliases': ['GHSA-cm5g-3pgc-8rg4'],
        'modified': '2024-12-19T17:52:09Z',
        'published': '2024-10-29T18:30:37Z',
        'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N'}],
        'affected': [{
            'package': {'ecosystem': 'npm', 'name': 'express'},
            'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '4.0.0-rc1'}]}],
            'versions': ['3.0.0', '3.1.0', '3.2.0', '3.3.0', '3.4.0', '3.5.0', '3.21.4']
        }],
        'summary': 'Express resource injection',
        'details': 'A vulnerability has been identified in the Express response.links function, allowing for arbitrary resource injection in the Link header when unsanitized data is used.',
        'database_specific': {'cwe_ids': ['CWE-74']},
        'references': [
            {'type': 'ADVISORY', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-10491'},
            {'type': 'WEB', 'url': 'https://github.com/expressjs/express/issues/6222'}
        ]
    },
    {
        'id': 'CVE-2018-1272',
        'aliases': ['GHSA-4487-x383-qpph'],
        'modified': '2024-12-05T05:30:27.932883Z',
        'published': '2018-10-17T20:27:47Z',
        'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
        'affected': [{
            'package': {'ecosystem': 'Maven', 'name': 'org.springframework:spring-core'},
            'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '4.3.15'}]}],
            'versions': ['4.0.0', '4.1.0', '4.2.0', '4.3.0', '4.3.10', '4.3.14']
        }],
        'summary': 'Possible privilege escalation in org.springframework:spring-core',
        'details': 'Spring Framework provide client-side support for multipart requests. When Spring MVC server receives input from a remote client and uses that input to make a multipart request to another server, it can be exposed to an attack.',
        'references': [
            {'type': 'ADVISORY', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2018-1272'},
            {'type': 'WEB', 'url': 'https://pivotal.io/security/cve-2018-1272'}
        ]
    },
    {
        'id': 'CVE-2023-29401',
        'aliases': ['GHSA-2c4m-59x9-fr2g', 'GO-2023-1737'],
        'modified': '2023-11-08T04:12:18.674169Z',
        'published': '2023-05-12T20:19:25Z',
        'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'}],
        'affected': [{
            'package': {'ecosystem': 'Go', 'name': 'github.com/gin-gonic/gin'},
            'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '1.3.1'}, {'fixed': '1.9.1'}]}],
            'versions': ['1.3.1', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0', '1.9.0']
        }],
        'summary': 'Gin Web Framework does not properly sanitize filename parameter',
        'details': 'The filename parameter of the Context.FileAttachment function is not properly sanitized. A maliciously crafted filename can cause the Content-Disposition header to be sent with an unexpected filename value.',
        'database_specific': {'cwe_ids': ['CWE-494']},
        'references': [
            {'type': 'ADVISORY', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-29401'},
            {'type': 'WEB', 'url': 'https://pkg.go.dev/vuln/GO-2023-1737'}
        ]
    }
]

def generate_pdf_report(vulnerabilities, filename='vuln_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=16, spaceAfter=12)
    story.append(Paragraph(f'Vulnerability Report - {datetime.now().strftime("%Y-%m-%d")} [TEST]', title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(f'Total Critical/High Vulnerabilities: {len(vulnerabilities)}', styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    for vuln in vulnerabilities:
        story.append(Paragraph(f"<b>ID:</b> {vuln.get('id', 'N/A')}", styles['Heading2']))
        if vuln.get('aliases'):
            story.append(Paragraph(f"<b>Aliases:</b> {', '.join(vuln['aliases'][:3])}", styles['Normal']))
        story.append(Paragraph(f"<b>Modified:</b> {vuln.get('modified', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Published:</b> {vuln.get('published', 'N/A')}", styles['Normal']))
        
        severity_info = vuln.get('severity', [])
        if severity_info:
            for sev in severity_info:
                story.append(Paragraph(f"<b>Severity ({sev.get('type', 'N/A')}):</b> {sev.get('score', 'N/A')}", styles['Normal']))
        
        affected = vuln.get('affected', [])
        if affected:
            pkg = affected[0].get('package', {})
            story.append(Paragraph(f"<b>Ecosystem:</b> {pkg.get('ecosystem', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Package:</b> {pkg.get('name', 'N/A')}", styles['Normal']))
        
        story.append(Paragraph(f"<b>Summary:</b> {vuln.get('summary', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
    
    doc.build(story)

def display_report(vulnerabilities):
    print('Test email notification - generating PDF...')

if __name__ == '__main__':
    display_report(SAMPLE_VULNERABILITIES)
    generate_pdf_report(SAMPLE_VULNERABILITIES)
