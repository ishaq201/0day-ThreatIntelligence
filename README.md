# Vulnerability Monitor

Monitors npm, Maven, PyPI, and Go ecosystems for critical/high severity vulnerabilities disclosed in the last 24 hours using OSV.dev API.

## Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Local Execution
```bash
python vuln_monitor.py
```

### GitHub Actions (Automated)

1. Push code to GitHub repository
2. Workflow runs automatically daily at 9 AM UTC
3. Download PDF reports from Actions > Artifacts
4. Manual trigger: Actions > Daily Vulnerability Scan > Run workflow

### Local Scheduling

**Cron (Linux/Mac):**
```bash
0 9 * * * cd /Users/ishaq/Ishaq/AppSec/0day-ThreatIntelligence && source venv/bin/activate && python vuln_monitor.py
```

**Task Scheduler (Windows):**
- Create task with trigger: Daily at 9:00 AM
- Action: Start program `python` with argument `vuln_monitor.py`

## Output

Generates:
- Console output with vulnerability summary
- `vuln_report.pdf` with comprehensive details:
  - Vulnerability ID and aliases
  - Severity (CVSS scores)
  - Affected ecosystem, package, and versions
  - Fixed version
  - Summary, details, CWE IDs
  - References

## Configuration

- **Ecosystems**: npm, Maven, PyPI, Go
- **Severity Filter**: CVSS >= 7.0 (High/Critical)
- **Time Window**: Last 24 hours
- **API**: OSV.dev (no authentication required)
