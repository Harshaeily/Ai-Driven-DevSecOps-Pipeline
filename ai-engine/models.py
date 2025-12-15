"""
Data models for the AI-Driven DevSecOps Pipeline
Defines common data structures for vulnerabilities, scan results, and reports
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities"""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    CRYPTOGRAPHIC = "CRYPTOGRAPHIC"
    DESERIALIZATION = "DESERIALIZATION"
    SSRF = "SSRF"
    XXE = "XXE"
    CSRF = "CSRF"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    OTHER = "OTHER"


class ScanSource(str, Enum):
    """Source of the vulnerability scan"""
    SAST = "SAST"
    DAST = "DAST"
    MANUAL = "MANUAL"


@dataclass
class Location:
    """Location information for a vulnerability"""
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None


@dataclass
class Vulnerability:
    """Represents a single security vulnerability"""
    id: str
    title: str
    description: str
    severity: Severity
    source: ScanSource
    location: Location
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: float = 1.0
    
    # Risk scoring
    risk_score: float = 0.0
    exploitability_score: float = 0.0
    business_impact_score: float = 0.0
    exposure_score: float = 0.0
    
    # False positive detection
    is_false_positive: bool = False
    false_positive_confidence: float = 0.0
    false_positive_reason: Optional[str] = None
    
    # Prioritization
    priority: int = 5
    remediation_effort: Optional[str] = None
    remediation_sla_days: Optional[int] = None
    
    # Additional metadata
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Remediation
    remediation_guidance: Optional[str] = None
    code_example: Optional[str] = None
    
    # Tracking
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanResult:
    """Results from a security scan"""
    scan_id: str
    scan_type: ScanSource
    scan_date: datetime
    vulnerabilities: List[Vulnerability]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities by severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_high_risk(self, threshold: float = 0.7) -> List[Vulnerability]:
        """Get high-risk vulnerabilities above threshold"""
        return [v for v in self.vulnerabilities if v.risk_score >= threshold]


@dataclass
class AnalysisReport:
    """Complete analysis report from AI engine"""
    report_id: str
    generated_at: datetime
    
    # Input scans
    sast_results: Optional[ScanResult] = None
    dast_results: Optional[ScanResult] = None
    
    # Processed vulnerabilities
    all_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    filtered_vulnerabilities: List[Vulnerability] = field(default_factory=list)
    top_priorities: List[Vulnerability] = field(default_factory=list)
    
    # Summary statistics
    summary: Dict[str, Any] = field(default_factory=dict)
    
    # Policy information
    policy_version: Optional[str] = None
    policy_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization"""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "policy": {
                "name": self.policy_name,
                "version": self.policy_version
            },
            "summary": self.summary,
            "vulnerabilities": {
                "total": len(self.all_vulnerabilities),
                "filtered": len(self.filtered_vulnerabilities),
                "top_priorities": len(self.top_priorities),
                "by_severity": self._count_by_severity(self.filtered_vulnerabilities),
                "by_source": self._count_by_source(self.filtered_vulnerabilities),
                "by_type": self._count_by_type(self.filtered_vulnerabilities)
            },
            "top_priorities": [self._vulnerability_to_dict(v) for v in self.top_priorities],
            "all_findings": [self._vulnerability_to_dict(v) for v in self.filtered_vulnerabilities]
        }
    
    def _count_by_severity(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {s.value: 0 for s in Severity}
        for v in vulns:
            counts[v.severity.value] += 1
        return counts
    
    def _count_by_source(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by source"""
        counts = {s.value: 0 for s in ScanSource}
        for v in vulns:
            counts[v.source.value] += 1
        return counts
    
    def _count_by_type(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts = {}
        for v in vulns:
            vuln_type = v.raw_data.get('type', 'OTHER')
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts
    
    def _vulnerability_to_dict(self, v: Vulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary"""
        return {
            "id": v.id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value,
            "source": v.source.value,
            "location": {
                "file": v.location.file_path,
                "line_start": v.location.line_start,
                "line_end": v.location.line_end,
                "url": v.location.url,
                "method": v.location.method,
                "parameter": v.location.parameter
            },
            "cwe": v.cwe,
            "owasp": v.owasp,
            "confidence": v.confidence,
            "risk_score": round(v.risk_score, 3),
            "priority": v.priority,
            "is_false_positive": v.is_false_positive,
            "false_positive_confidence": round(v.false_positive_confidence, 3),
            "false_positive_reason": v.false_positive_reason,
            "remediation": {
                "guidance": v.remediation_guidance,
                "code_example": v.code_example,
                "effort": v.remediation_effort,
                "sla_days": v.remediation_sla_days
            },
            "tags": v.tags,
            "references": v.references
        }


@dataclass
class PolicyConfig:
    """Security policy configuration"""
    version: str
    policy_name: str
    
    # Severity configuration
    severity_weights: Dict[str, float]
    severity_threshold: str
    blocking_severities: List[str]
    
    # False positive detection
    fp_enabled: bool
    fp_confidence_threshold: float
    fp_file_patterns: List[str]
    fp_code_patterns: List[Dict[str, str]]
    
    # Risk scoring
    risk_factors: Dict[str, float]
    exploitability_scores: Dict[str, float]
    business_impact_scores: Dict[str, float]
    exposure_scores: Dict[str, float]
    
    # Prioritization
    top_priority_limit: int
    auto_priority_rules: List[Dict[str, Any]]
    
    # Remediation SLA
    sla_by_priority: Dict[int, int]
    sla_by_severity: Dict[str, int]
    
    # Raw config for reference
    raw_config: Dict[str, Any] = field(default_factory=dict)
