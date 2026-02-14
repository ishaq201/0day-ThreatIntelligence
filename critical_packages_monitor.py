#!/usr/bin/env python3
import requests
from datetime import datetime, timedelta, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

CRITICAL_PACKAGES = {
    'npm': ['lodash', 'express', 'react', 'axios', 'webpack', 'next', 'typescript', 'eslint', 'moment', 'request'],
    'Maven': [
        'org.springframework:spring-core',
        'org.apache.logging.log4j:log4j-core',
        'com.fasterxml.jackson.core:jackson-databind',
        'org.apache.commons:commons-lang3',
        'org.hibernate:hibernate-core',
        'org.springframework.boot:spring-boot-starter-web',
        'com.google.guava:guava',
        'org.apache.tomcat.embed:tomcat-embed-core',
        'org.slf4j:slf4j-api',
        'junit:junit'
    ],
    'PyPI': ['requests', 'urllib3', 'setuptools', 'pip', 'django', 'flask', 'numpy', 'cryptography', 'pillow', 'pyyaml'],
    'Go': [
        'golang.org/x/crypto',
        'github.com/gin-gonic/gin',
        'github.com/gorilla/mux',
        'github.com/sirupsen/logrus',
        'google.golang.org/grpc',
        'github.com/stretchr/testify',
        'golang.org/x/net',
        'github.com/go-sql-driver/mysql',
        'github.com/lib/pq',
        'github.com/spf13/cobra'
    ]
}

def query_package_vulns(ecosystem, package):
    url = 'https://api.osv.dev/v1/query'
    payload = {'package': {'ecosystem': ecosystem, 'name': package}}
    response = requests.post(url, json=payload)
    return response.json().get('vulns', [])

def get_vuln_details(vuln_id):
    url = f'https://api.osv.dev/v1/vulns/{vuln_id}'
    response = requests.get(url)
    return response.json()

def filter_recent_and_severity(vulns, modified_after):
    filtered = []
    for vuln in vulns:
        details = get_vuln_details(vuln['id'])
        
        if details.get('modified', '') < modified_after:
            continue
        
        severity = details.get('severity', [{}])[0].get('type')
        score = details.get('severity', [{}])[0].get('score')
        
        if severity == 'CVSS_V3' and score:
            cvss_score = float(score.split(':')[1].split('/')[0]) if ':' in score else 0
            if cvss_score >= 7.0:
                filtered.append(details)
        elif any(s in str(details.get('database_specific', {})).upper() for s in ['CRITICAL', 'HIGH']):
            filtered.append(details)
    return filtered

def generate_pdf_report(vulnerabilities, filename='critical_packages_report.pdf'):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=16, spaceAfter=12)
    story.append(Paragraph(f'Critical Packages Vulnerability Report - {datetime.now().strftime("%Y-%m-%d")}', title_style))
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

def main():
    modified_after = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    all_vulns = []
    
    for ecosystem, packages in CRITICAL_PACKAGES.items():
        print(f'Querying {ecosystem}...')
        for package in packages:
            print(f'  Checking {package}...')
            vulns = query_package_vulns(ecosystem, package)
            if vulns:
                filtered = filter_recent_and_severity(vulns, modified_after)
                if filtered:
                    all_vulns.extend(filtered)
                    print(f'    Found {len(filtered)} critical/high vulnerabilities')
    
    print(f'\n{"="*100}')
    print(f'Total vulnerabilities found: {len(all_vulns)}')
    print(f'{"="*100}\n')
    
    if all_vulns:
        generate_pdf_report(all_vulns)
    else:
        print('No critical/high vulnerabilities found in the last 24 hours')

if __name__ == '__main__':
    main()
