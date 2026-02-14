#!/usr/bin/env python3
import requests
from datetime import datetime, timedelta, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

import zipfile
from io import BytesIO
import json

ECOSYSTEMS = ['npm', 'Maven', 'PyPI', 'Go']
SEVERITY_FILTER = ['CRITICAL', 'HIGH']

def download_ecosystem_vulns(ecosystem, modified_after):
    """Download and filter vulnerabilities from OSV database dump"""
    url = f'https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip'
    print(f'  Downloading {ecosystem} database...')
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        vulns = []
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            for filename in z.namelist()[:500]:  # Limit to first 500 for speed
                with z.open(filename) as f:
                    vuln = json.load(f)
                    # Check if modified recently
                    if vuln.get('modified', '') >= modified_after:
                        vulns.append({'id': vuln['id']})
        return vulns
    except Exception as e:
        print(f'  Error downloading {ecosystem}: {e}')
        return []

def get_vuln_details(vuln_id):
    url = f'https://api.osv.dev/v1/vulns/{vuln_id}'
    response = requests.get(url)
    return response.json()

def filter_by_severity(vulns):
    filtered = []
    for vuln in vulns:
        details = get_vuln_details(vuln['id'])
        severity = details.get('severity', [{}])[0].get('type')
        score = details.get('severity', [{}])[0].get('score')
        
        if severity == 'CVSS_V3' and score:
            cvss_score = float(score.split(':')[1].split('/')[0]) if ':' in score else 0
            if cvss_score >= 7.0:
                filtered.append(details)
        elif any(s in str(details.get('database_specific', {})).upper() for s in SEVERITY_FILTER):
            filtered.append(details)
    return filtered

def generate_pdf_report(vulnerabilities, filename='vuln_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=16, spaceAfter=12)
    story.append(Paragraph(f'Vulnerability Report - {datetime.now().strftime("%Y-%m-%d")}', title_style))
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
            
            ranges = affected[0].get('ranges', [])
            if ranges:
                for r in ranges:
                    if r.get('type') in ['ECOSYSTEM', 'SEMVER']:
                        events = r.get('events', [])
                        if events:
                            fixed = next((e.get('fixed') for e in events if 'fixed' in e), None)
                            if fixed:
                                story.append(Paragraph(f"<b>Fixed In:</b> {fixed}", styles['Normal']))
            
            versions = affected[0].get('versions', [])
            if versions:
                story.append(Paragraph(f"<b>Affected Versions:</b> {', '.join(versions[:15])}{' ...' if len(versions) > 15 else ''}", styles['Normal']))
        
        story.append(Paragraph(f"<b>Summary:</b> {vuln.get('summary', 'N/A')}", styles['Normal']))
        
        details = vuln.get('details', '')
        if details and details != vuln.get('summary'):
            story.append(Paragraph(f"<b>Details:</b> {details[:500]}...", styles['Normal']))
        
        db_specific = vuln.get('database_specific', {})
        if db_specific and db_specific.get('cwe_ids'):
            story.append(Paragraph(f"<b>CWE IDs:</b> {', '.join(db_specific['cwe_ids'])}", styles['Normal']))
        
        refs = vuln.get('references', [])
        if refs:
            story.append(Paragraph(f"<b>References:</b>", styles['Normal']))
            for ref in refs[:3]:
                story.append(Paragraph(f"  • {ref.get('url', 'N/A')}", styles['Normal']))
        
        story.append(Spacer(1, 0.4*inch))
    
    doc.build(story)
    print(f'PDF report generated: {filename}')

def display_report(vulnerabilities):
    print(f'\n{"="*100}')
    print(f'Vulnerability Report - {datetime.now().strftime("%Y-%m-%d")}')
    print(f'Total Critical/High Vulnerabilities: {len(vulnerabilities)}')
    print(f'{"="*100}\n')

def main():
    modified_after = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    all_vulns = []
    
    for ecosystem in ECOSYSTEMS:
        print(f'Querying {ecosystem}...')
        vulns = download_ecosystem_vulns(ecosystem, modified_after)
        if vulns:
            filtered = filter_by_severity(vulns)
            all_vulns.extend(filtered)
            print(f'Found {len(filtered)} critical/high vulnerabilities in {ecosystem}')
    
    if all_vulns:
        display_report(all_vulns)
        generate_pdf_report(all_vulns)
    else:
        print('No critical/high vulnerabilities found in the last 24 hours')

if __name__ == '__main__':
    main()
