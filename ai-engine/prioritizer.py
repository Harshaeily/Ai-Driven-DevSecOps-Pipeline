"""
Vulnerability Prioritizer for the AI-Driven DevSecOps Pipeline
Prioritizes vulnerabilities based on risk scores and policy rules
"""

from typing import List
from models import Vulnerability, PolicyConfig, Severity


class VulnerabilityPrioritizer:
    """Prioritizes vulnerabilities for remediation"""
    
    def __init__(self, policy: PolicyConfig):
        """
        Initialize prioritizer
        
        Args:
            policy: Policy configuration
        """
        self.policy = policy
        self.auto_priority_rules = policy.auto_priority_rules
        self.top_priority_limit = policy.top_priority_limit
    
    def prioritize(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Assign priority levels to vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities with risk scores
            
        Returns:
            List with priorities assigned
        """
        # Filter out false positives
        real_vulns = [v for v in vulnerabilities if not v.is_false_positive]
        
        # Apply auto-priority rules
        for vuln in real_vulns:
            priority = self._apply_auto_rules(vuln)
            if priority:
                vuln.priority = priority
            else:
                # Default priority based on risk score
                vuln.priority = self._calculate_default_priority(vuln)
            
            # Assign remediation SLA
            vuln.remediation_sla_days = self.policy.sla_by_priority.get(
                vuln.priority,
                self.policy.sla_by_severity.get(vuln.severity.value, 90)
            )
            
            # Estimate remediation effort
            vuln.remediation_effort = self._estimate_effort(vuln)
        
        return vulnerabilities
    
    def get_top_priorities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Get top priority vulnerabilities
        
        Args:
            vulnerabilities: List of prioritized vulnerabilities
            
        Returns:
            Top N vulnerabilities by priority and risk score
        """
        # Filter real vulnerabilities
        real_vulns = [v for v in vulnerabilities if not v.is_false_positive]
        
        # Sort by priority (ascending) then risk score (descending)
        sorted_vulns = sorted(
            real_vulns,
            key=lambda v: (v.priority, -v.risk_score)
        )
        
        return sorted_vulns[:self.top_priority_limit]
    
    def _apply_auto_rules(self, vuln: Vulnerability) -> int:
        """
        Apply automatic priority rules
        
        Args:
            vuln: Vulnerability to check
            
        Returns:
            Priority level (1-5) or None if no rule matches
        """
        for rule in self.auto_priority_rules:
            if self._matches_rule(vuln, rule):
                return rule.get('priority', 3)
        
        return None
    
    def _matches_rule(self, vuln: Vulnerability, rule: dict) -> bool:
        """Check if vulnerability matches a priority rule"""
        conditions = rule.get('conditions', {})
        
        # Check severity condition
        severity_list = conditions.get('severity', [])
        if severity_list and vuln.severity.value not in severity_list:
            return False
        
        # Check CWE condition
        cwe_list = conditions.get('cwe', [])
        if cwe_list and vuln.cwe not in cwe_list:
            return False
        
        # Check OWASP condition
        owasp_list = conditions.get('owasp', [])
        if owasp_list and vuln.owasp not in owasp_list:
            return False
        
        # Check risk score threshold
        min_risk = conditions.get('min_risk_score')
        if min_risk and vuln.risk_score < min_risk:
            return False
        
        return True
    
    def _calculate_default_priority(self, vuln: Vulnerability) -> int:
        """
        Calculate default priority based on risk score
        
        Args:
            vuln: Vulnerability
            
        Returns:
            Priority level (1-5)
        """
        risk_score = vuln.risk_score
        
        if risk_score >= 0.9:
            return 1  # Critical priority
        elif risk_score >= 0.7:
            return 2  # High priority
        elif risk_score >= 0.5:
            return 3  # Medium priority
        elif risk_score >= 0.3:
            return 4  # Low priority
        else:
            return 5  # Info priority
    
    def _estimate_effort(self, vuln: Vulnerability) -> str:
        """
        Estimate remediation effort
        
        Args:
            vuln: Vulnerability
            
        Returns:
            Effort estimate (LOW, MEDIUM, HIGH)
        """
        cwe = vuln.cwe
        
        # Low effort - configuration changes
        low_effort_cwes = ['CWE-798', 'CWE-489', 'CWE-330']  # Hardcoded secrets, debug mode, weak random
        if cwe in low_effort_cwes:
            return "LOW"
        
        # High effort - architectural changes
        high_effort_cwes = ['CWE-287', 'CWE-306', 'CWE-502']  # Auth bypass, missing auth, deserialization
        if cwe in high_effort_cwes:
            return "HIGH"
        
        # Medium effort - code changes
        return "MEDIUM"
    
    def get_statistics(self, vulnerabilities: List[Vulnerability]) -> dict:
        """
        Get prioritization statistics
        
        Args:
            vulnerabilities: List of prioritized vulnerabilities
            
        Returns:
            Statistics dictionary
        """
        real_vulns = [v for v in vulnerabilities if not v.is_false_positive]
        
        priority_counts = {}
        for i in range(1, 6):
            priority_counts[f"priority_{i}"] = sum(1 for v in real_vulns if v.priority == i)
        
        effort_counts = {
            'low_effort': sum(1 for v in real_vulns if v.remediation_effort == 'LOW'),
            'medium_effort': sum(1 for v in real_vulns if v.remediation_effort == 'MEDIUM'),
            'high_effort': sum(1 for v in real_vulns if v.remediation_effort == 'HIGH')
        }
        
        return {
            **priority_counts,
            **effort_counts,
            'total_prioritized': len(real_vulns)
        }
