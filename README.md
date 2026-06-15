# INVA - Intelligent Network Vulnerability Analyzer

## Overview

INVA (Intelligent Network Vulnerability Analyzer) is a cybersecurity platform designed to identify, analyze, and prioritize security vulnerabilities across networked systems. The project combines network scanning, vulnerability assessment, threat intelligence, and risk analysis to provide a comprehensive view of an organization's security posture.

Unlike traditional scanners that only report open ports and services, INVA correlates discovered assets with vulnerability databases and threat intelligence sources to generate meaningful risk assessments and actionable remediation recommendations.

---

## Problem Statement

Organizations often struggle to identify vulnerable services, prioritize security risks, and understand the real-world impact of discovered vulnerabilities. Existing solutions can be expensive, complex, or provide large amounts of raw data without proper context.

INVA addresses this challenge by automating the process of network discovery, vulnerability analysis, risk scoring, and reporting within a single platform.

---

## Objectives

The primary objectives of INVA are:

- Discover exposed network services.
- Detect known vulnerabilities in identified services.
- Analyze risk based on vulnerability severity and threat intelligence.
- Provide remediation recommendations.
- Generate professional security assessment reports.
- Assist security teams in prioritizing mitigation efforts.

---

## Key Features

INVA provides a complete vulnerability assessment workflow that includes:

- Network and port scanning
- Service identification and version detection
- CVE-based vulnerability analysis
- Risk scoring and severity classification
- Threat intelligence integration
- Exploit availability detection
- Interactive security dashboard
- Automated report generation
- Historical scan tracking

---
## Installation and Usage

### Installation

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/rootXdeb/INVA.git
cd INVA
```

Create and activate a virtual environment:

**Linux/macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows**

```cmd
python -m venv venv
venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
python main.py
```

The application will be available at:

```text
http://127.0.0.1:5000
```

---

### Usage

1. Open the web interface in your browser.
2. Enter a target IP address, domain name, or URL.
3. Click **Start Scan** to begin the assessment.
4. The platform will automatically:

   * Scan open ports
   * Detect running services
   * Analyze potential vulnerabilities
   * Calculate risk scores
   * Perform threat intelligence checks
   * Map findings to OWASP Top 10 categories
5. Review the generated results and recommendations on the dashboard.
6. Export the scan results as **PDF** or **JSON** reports for documentation and further analysis.

**Example Targets**

```text
192.168.1.1
scanme.nmap.org
https://example.com
```


Disclaimer:
INVA is intended strictly for educational, research, and authorized security testing purposes. Users must obtain proper permission before scanning or assessing any network, system, or device. Unauthorized scanning may violate organizational policies and local laws.
