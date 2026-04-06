A system that analyzes code or infrastructure to identify security vulnerabilities and provide recommended remediation actions.

# AI Security Auditing Framework

## Overview

This framework provides comprehensive security auditing capabilities for generative AI systems, focusing on identifying and mitigating various threat vectors including prompt injection, training data leakage, and adversarial attacks.

## Risk Classification System

The framework employs a 5-level risk classification system to categorize security threats:

- **LOW**: Minimal security risk (Score: 0.0-0.2)
- **MEDIUM**: Moderate security concerns (Score: 0.2-0.4)
- **HIGH**: Significant vulnerabilities (Score: 0.4-0.6)
- **CRITICAL**: Severe security flaws (Score: 0.6-0.8)
- **EXTREME**: Catastrophic security risks (Score: 0.8+)

Each level provides specific guidance on required actions, from continued monitoring to emergency response procedures.

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from ai_security_auditor import AuditFramework
from ai_security_auditor.auditors import PromptInjectionAuditor
from ai_security_auditor.models import ThreatType

framework = AuditFramework()

available_threats = framework.get_available_threat_types()
print(f"📋 Available threat types: {[t.value for t in available_threats]}")

# Configure audit parameters
threat_types_to_test = [
    ThreatType.PROMPT_INJECTION,
]

# Load threat vectors
vectors = prompt_injection_vectors


framework.load_threat_vectors(ThreatType.PROMPT_INJECTION, vectors)

# Create audit configuration
config = AuditConfiguration(
    threat_types=threat_types_to_test,
    test_intensity="normal",  # "light", "normal", "comprehensive"
    max_test_time=300,        # 5 minutes max
    include_red_team=True,
    compliance_standards=["GDPR", "SOC2", "ISO27001"]
)

# Init Model Name
model_name = AIModel.QWEN3

print(f"🚀 Starting security audit of model: {model_name}")
print(f"🎯 Testing for {len(threat_types_to_test)} threat types...")

# Conduct the security audit
vulnerability_report = framework.audit_model(
    model_name=model_name.value,
    threat_types=threat_types_to_test,
    config=config,
)
```

## Project Structure

```
ai_security_auditor/
├── models/
│   ├── __init__.py
│   ├── threat_models.py
│   └── audit_models.py
├── auditors/
│   ├── __init__.py
│   ├── base_auditor.py
│   ├── prompt_injection.py
│   ├── data_leakage.py
│   └── adversarial.py
├── database/
│   ├── __init__.py
│   └── security_db.py
├── utils/
│   ├── __init__.py
│   ├── analysis.py
│   └── visualization.py
├── framework.py
├── auditor_usage.ipynb
└── cli.py
```

## 🛠️ Framework Architecture

### **Core Components**

```
AuditFramework
├── SecurityAnalyzer          # Trend analysis, anomaly detection
├── RiskCalculator           # Business risk, impact assessment
├── SecurityVisualizer       # Interactive charts & plots
├── ReportGenerator         # Enhanced report generation
├── SecurityDatabase        # Threat vector & audit storage
└── Auditor Registry        # Pluggable auditor system
```

### **Data Flow**

```
Model Input → Auditors → AuditResults → Analysis → Vissualizations → Reports
     ↓           ↓           ↓            ↓           ↓           ↓
   Models    Threat      Security     Advanced    Interactive  Enhanced
   & Config  Vectors    Database     Analytics    Charts      Reports
```

## 📋 Complete API Reference

### **Analysis Methods**

- `analyze_vulnerability_trends(time_window_days)` - Temporal trend analysis
- `calculate_composite_risk_score(audit_results)` - Advanced risk scoring
- `detect_anomalies(threshold)` - Statistical anomaly detection
- `analyze_security_posture(model_name)` - Comprehensive posture assessment
- `calculate_business_risk(report, context)` - Business impact analysis

### **Visualization Methods**

- `create_risk_matrix_visualization(risk_matrix)` - Interactive risk matrix
- `create_vulnerability_timeline()` - Temporal vulnerability chart
- `create_threat_comparison_chart()` - Threat severity comparison
- `create_model_comparison_radar(data)` - Multi-dimensional comparison

### **Enhanced Reporting**

- `generate_enhanced_report(report, include_viz, format)` - Full reports with charts
- `generate_executive_summary(report)` - Executive-level summaries
- `generate_security_dashboard_data()` - Dashboard data generation
- `export_audit_data(path, include_tests)` - Comprehensive data export

- Identify processes that will be adopted in the project, such as
  o Versioning system
  o User-Centred Design Process
