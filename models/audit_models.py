from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from models.threat_models import ThreatType, RiskLevel

@dataclass
class TestCase:
    """Represents a single security test case"""
    id: str
    threat_type: ThreatType
    test_input: str
    expected_behavior: str
    actual_output: str = ""
    vulnerability_score: float = 0.0
    success: bool = False
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AuditResult:
    """Represents the result of a security audit"""
    timestamp: datetime
    threat_type: ThreatType
    vulnerability_score: float  # 0-1, higher = more vulnerable
    confidence_score: float     # 0-1, confidence in the assessment
    evidence: List[str]
    test_cases: List[TestCase]
    recommendations: List[str]
    test_details: Dict[str, Any]
    false_positive_rate: Optional[float] = None
    execution_time: float = 0.0

@dataclass
class VulnerabilityReport:
    """Comprehensive vulnerability assessment report"""
    model_name: str
    audit_timestamp: datetime
    overall_risk_score: float
    risk_level: RiskLevel
    audit_results: List[AuditResult]
    risk_matrix: Dict[str, Dict[str, float]]
    recommendations: List[str]
    compliance_status: Dict[str, bool]
    executive_summary: str
    technical_details: Dict[str, Any]
    execution_time: float = 0.0
    
    @property
    def total_vulnerabilities(self) -> int:
        """Count total number of vulnerabilities found"""
        return sum(1 for result in self.audit_results if result.vulnerability_score > 0.5)
    
    @property
    def critical_vulnerabilities(self) -> int:
        """Count critical vulnerabilities"""
        return sum(1 for result in self.audit_results if result.vulnerability_score > 0.8)
    
@dataclass
class AuditConfiguration:
    """Configuration for security audits"""
    threat_types: List[ThreatType]
    test_intensity: str  # "light", "normal", "comprehensive"
    max_test_time: int  # seconds
    include_red_team: bool = True
    custom_prompts: List[str] = field(default_factory=list)
    compliance_standards: List[str] = field(default_factory=list)
    output_format: str = "json"  # "json", "pdf", "html"