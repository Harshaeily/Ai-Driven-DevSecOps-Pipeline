"""
False Positive Detector for the AI-Driven DevSecOps Pipeline
Intelligently identifies and filters false positive vulnerabilities
"""

import re
from typing import List
from pathlib import Path
from models import Vulnerability, PolicyConfig


class FalsePositiveDetector:
    """Detects and filters false positive vulnerabilities"""
    
    def __init__(self, policy: PolicyConfig):
        """
        Initialize false positive detector
        
        Args:
            policy: Policy configuration
        """
        self.policy = policy
        self.enabled = policy.fp_enabled
        self.confidence_threshold = policy.fp_confidence_threshold
    
    def analyze(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Analyze vulnerabilities and mark false positives
        
        Args:
            vulnerabilities: List of vulnerabilities to analyze
            
        Returns:
            List of vulnerabilities with FP flags set
        """
        if not self.enabled:
            return vulnerabilities
        
        for vuln in vulnerabilities:
            fp_score, reason = self._calculate_fp_score(vuln)
            vuln.false_positive_confidence = fp_score
            vuln.false_positive_reason = reason
            
            # Mark as false positive if confidence exceeds threshold
            if fp_score >= self.confidence_threshold:
                vuln.is_false_positive = True
        
        return vulnerabilities
    
    def filter_false_positives(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Filter out false positives from vulnerability list
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Filtered list without false positives
        """
        return [v for v in vulnerabilities if not v.is_false_positive]
    
    def _calculate_fp_score(self, vuln: Vulnerability) -> tuple[float, str]:
        """
        Calculate false positive confidence score
        
        Args:
            vuln: Vulnerability to analyze
            
        Returns:
            Tuple of (confidence score 0-1, reason)
        """
        scores = []
        reasons = []
        
        # Check file path patterns
        file_score, file_reason = self._check_file_patterns(vuln)
        if file_score > 0:
            scores.append(file_score)
            reasons.append(file_reason)
        
        # Check code patterns
        code_score, code_reason = self._check_code_patterns(vuln)
        if code_score > 0:
            scores.append(code_score)
            reasons.append(code_reason)
        
        # Check context indicators
        context_score, context_reason = self._check_context(vuln)
        if context_score > 0:
            scores.append(context_score)
            reasons.append(context_reason)
        
        # Check confidence level from scanner
        scanner_score, scanner_reason = self._check_scanner_confidence(vuln)
        if scanner_score > 0:
            scores.append(scanner_score)
            reasons.append(scanner_reason)
        
        # Calculate weighted average
        if scores:
            final_score = sum(scores) / len(scores)
            final_reason = "; ".join(reasons)
        else:
            final_score = 0.0
            final_reason = "No false positive indicators"
        
        return final_score, final_reason
    
    def _check_file_patterns(self, vuln: Vulnerability) -> tuple[float, str]:
        """Check if vulnerability is in excluded file patterns"""
        file_path = vuln.location.file_path.lower()
        
        for pattern in self.policy.fp_file_patterns:
            # Convert glob pattern to regex
            regex_pattern = pattern.replace('*', '.*').replace('?', '.').lower()
            if re.search(regex_pattern, file_path):
                return 0.9, f"File matches excluded pattern: {pattern}"
        
        # Check for common test/build directories
        test_indicators = ['/test/', '/tests/', '_test.', '/node_modules/', '/vendor/', 
                          '/dist/', '/build/', '.min.', '/mock/', '/fixture/']
        for indicator in test_indicators:
            if indicator in file_path:
                return 0.85, f"File appears to be in test/build directory: {indicator}"
        
        return 0.0, ""
    
    def _check_code_patterns(self, vuln: Vulnerability) -> tuple[float, str]:
        """Check if code contains false positive indicators"""
        # Get code snippet from raw data
        code_lines = vuln.raw_data.get('lines', '')
        if not code_lines:
            return 0.0, ""
        
        code_lower = code_lines.lower()
        
        # Check for explicit security exceptions
        for pattern_config in self.policy.fp_code_patterns:
            pattern = pattern_config.get('pattern', '').lower()
            if pattern and pattern in code_lower:
                description = pattern_config.get('description', 'Security exception marker')
                return 0.95, f"Code contains exception marker: {description}"
        
        # Check for common false positive patterns
        fp_patterns = [
            ('# nosec', 'Bandit security exception'),
            ('# noqa', 'Linting exception'),
            ('# pragma: allowlist', 'Security allowlist'),
            ('# safe:', 'Marked as safe'),
            ('# reviewed:', 'Security reviewed'),
            ('# false positive', 'Explicitly marked as FP')
        ]
        
        for pattern, description in fp_patterns:
            if pattern in code_lower:
                return 0.9, description
        
        return 0.0, ""
    
    def _check_context(self, vuln: Vulnerability) -> tuple[float, str]:
        """Check contextual indicators"""
        # Check if in test code based on function/class names
        code_lines = vuln.raw_data.get('lines', '').lower()
        
        test_indicators = ['def test_', 'class test', 'def mock_', 'def fixture_',
                          'unittest.', 'pytest.', '@mock', '@patch']
        
        for indicator in test_indicators:
            if indicator in code_lines:
                return 0.8, f"Appears to be test code: {indicator}"
        
        # Check for example/demo code
        example_indicators = ['example', 'demo', 'sample', 'tutorial']
        file_path = vuln.location.file_path.lower()
        
        for indicator in example_indicators:
            if indicator in file_path:
                return 0.7, f"Appears to be example/demo code: {indicator}"
        
        # Check for commented out code
        if code_lines.strip().startswith('#') or code_lines.strip().startswith('//'):
            return 0.6, "Code appears to be commented out"
        
        return 0.0, ""
    
    def _check_scanner_confidence(self, vuln: Vulnerability) -> tuple[float, str]:
        """Check scanner's own confidence level"""
        scanner_confidence = vuln.confidence
        
        # If scanner itself has low confidence, increase FP score
        if scanner_confidence < 0.5:
            fp_score = 1.0 - scanner_confidence
            return fp_score, f"Low scanner confidence: {scanner_confidence:.2f}"
        
        return 0.0, ""
    
    def get_statistics(self, vulnerabilities: List[Vulnerability]) -> dict:
        """
        Get false positive detection statistics
        
        Args:
            vulnerabilities: List of analyzed vulnerabilities
            
        Returns:
            Statistics dictionary
        """
        total = len(vulnerabilities)
        false_positives = sum(1 for v in vulnerabilities if v.is_false_positive)
        true_positives = total - false_positives
        
        fp_rate = (false_positives / total * 100) if total > 0 else 0
        
        # Group by FP reason
        fp_reasons = {}
        for v in vulnerabilities:
            if v.is_false_positive and v.false_positive_reason:
                reason = v.false_positive_reason.split(';')[0]  # First reason
                fp_reasons[reason] = fp_reasons.get(reason, 0) + 1
        
        return {
            'total_vulnerabilities': total,
            'false_positives': false_positives,
            'true_positives': true_positives,
            'false_positive_rate': round(fp_rate, 2),
            'fp_reasons': fp_reasons
        }
