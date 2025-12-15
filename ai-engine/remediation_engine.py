"""
Remediation Engine for the AI-Driven DevSecOps Pipeline
Generates actionable remediation guidance for vulnerabilities
"""

from typing import Dict, Optional
from models import Vulnerability


class RemediationEngine:
    """Generates remediation guidance for vulnerabilities"""
    
    def __init__(self):
        """Initialize remediation engine"""
        self.remediation_templates = self._load_templates()
    
    def generate_guidance(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """
        Generate remediation guidance for all vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List with remediation guidance added
        """
        for vuln in vulnerabilities:
            if vuln.is_false_positive:
                continue
            
            guidance, code_example = self._get_remediation(vuln)
            vuln.remediation_guidance = guidance
            vuln.code_example = code_example
        
        return vulnerabilities
    
    def _get_remediation(self, vuln: Vulnerability) -> tuple[str, Optional[str]]:
        """
        Get remediation guidance for a vulnerability
        
        Args:
            vuln: Vulnerability
            
        Returns:
            Tuple of (guidance text, code example)
        """
        cwe = vuln.cwe
        
        # Try to find specific remediation for CWE
        if cwe and cwe in self.remediation_templates:
            template = self.remediation_templates[cwe]
            return template['guidance'], template.get('code_example')
        
        # Fall back to generic guidance based on severity
        return self._get_generic_guidance(vuln), None
    
    def _get_generic_guidance(self, vuln: Vulnerability) -> str:
        """Get generic remediation guidance"""
        return (
            f"Review and remediate this {vuln.severity.value} severity vulnerability. "
            f"Consult security best practices and OWASP guidelines for {vuln.title}. "
            f"Consider the business impact and prioritize accordingly."
        )
    
    def _load_templates(self) -> Dict[str, Dict]:
        """Load remediation templates for common CWEs"""
        return {
            'CWE-89': {
                'guidance': (
                    "SQL Injection Remediation:\n"
                    "1. Use parameterized queries (prepared statements) instead of string concatenation\n"
                    "2. Use ORM frameworks with built-in protection\n"
                    "3. Implement input validation and sanitization\n"
                    "4. Apply principle of least privilege for database accounts\n"
                    "5. Use stored procedures with parameterized inputs"
                ),
                'code_example': '''# Vulnerable code:
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# Secure code:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))'''
            },
            
            'CWE-79': {
                'guidance': (
                    "Cross-Site Scripting (XSS) Remediation:\n"
                    "1. Enable auto-escaping in template engines\n"
                    "2. Use Content Security Policy (CSP) headers\n"
                    "3. Sanitize user input before rendering\n"
                    "4. Use framework-provided escaping functions\n"
                    "5. Validate and encode output based on context (HTML, JavaScript, URL)"
                ),
                'code_example': '''# Vulnerable code:
return render_template_string(f"<h1>Hello {user_input}</h1>")

# Secure code:
from markupsafe import escape
return render_template_string(f"<h1>Hello {escape(user_input)}</h1>")'''
            },
            
            'CWE-78': {
                'guidance': (
                    "Command Injection Remediation:\n"
                    "1. Avoid shell=True in subprocess calls\n"
                    "2. Use subprocess with argument lists instead of shell commands\n"
                    "3. Validate and whitelist allowed commands\n"
                    "4. Use libraries instead of shell commands when possible\n"
                    "5. Implement strict input validation"
                ),
                'code_example': '''# Vulnerable code:
subprocess.call(f"ls {user_path}", shell=True)

# Secure code:
subprocess.call(["ls", user_path])'''
            },
            
            'CWE-798': {
                'guidance': (
                    "Hardcoded Credentials Remediation:\n"
                    "1. Move secrets to environment variables\n"
                    "2. Use secret management systems (AWS Secrets Manager, HashiCorp Vault)\n"
                    "3. Implement proper key rotation\n"
                    "4. Never commit secrets to version control\n"
                    "5. Use .gitignore for sensitive configuration files"
                ),
                'code_example': '''# Vulnerable code:
API_KEY = "sk_live_1234567890abcdef"

# Secure code:
import os
API_KEY = os.environ.get("API_KEY")'''
            },
            
            'CWE-287': {
                'guidance': (
                    "Authentication Bypass Remediation:\n"
                    "1. Implement proper authentication checks on all protected endpoints\n"
                    "2. Use established authentication frameworks\n"
                    "3. Implement multi-factor authentication (MFA)\n"
                    "4. Use secure session management\n"
                    "5. Implement account lockout after failed attempts"
                ),
                'code_example': '''# Vulnerable code:
@app.route('/admin')
def admin():
    return render_template('admin.html')

# Secure code:
from flask_login import login_required

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin.html')'''
            },
            
            'CWE-327': {
                'guidance': (
                    "Weak Cryptography Remediation:\n"
                    "1. Use SHA-256 or better instead of MD5/SHA-1\n"
                    "2. Use bcrypt, scrypt, or Argon2 for password hashing\n"
                    "3. Use AES-256 for encryption\n"
                    "4. Implement proper key management\n"
                    "5. Use TLS 1.2+ for data in transit"
                ),
                'code_example': '''# Vulnerable code:
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()

# Secure code:
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())'''
            },
            
            'CWE-502': {
                'guidance': (
                    "Insecure Deserialization Remediation:\n"
                    "1. Avoid deserializing untrusted data\n"
                    "2. Use safe serialization formats (JSON instead of pickle)\n"
                    "3. Implement integrity checks (HMAC signatures)\n"
                    "4. Use allowlists for deserializable classes\n"
                    "5. Run deserialization in sandboxed environments"
                ),
                'code_example': '''# Vulnerable code:
import pickle
data = pickle.loads(user_input)

# Secure code:
import json
data = json.loads(user_input)'''
            },
            
            'CWE-22': {
                'guidance': (
                    "Path Traversal Remediation:\n"
                    "1. Validate and sanitize file paths\n"
                    "2. Use allowlists for permitted files/directories\n"
                    "3. Use os.path.basename() to strip directory components\n"
                    "4. Implement chroot jails or similar containment\n"
                    "5. Avoid direct file system access when possible"
                ),
                'code_example': '''# Vulnerable code:
with open(f"/uploads/{user_file}") as f:
    content = f.read()

# Secure code:
import os
safe_path = os.path.join("/uploads", os.path.basename(user_file))
if not safe_path.startswith("/uploads/"):
    raise ValueError("Invalid path")
with open(safe_path) as f:
    content = f.read()'''
            },
            
            'CWE-352': {
                'guidance': (
                    "CSRF Remediation:\n"
                    "1. Implement CSRF tokens for state-changing operations\n"
                    "2. Use SameSite cookie attribute\n"
                    "3. Verify Origin and Referer headers\n"
                    "4. Use framework-provided CSRF protection\n"
                    "5. Require re-authentication for sensitive operations"
                ),
                'code_example': '''# Vulnerable code:
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    process_transfer(amount)

# Secure code:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.protect
def transfer():
    amount = request.form['amount']
    process_transfer(amount)'''
            },
            
            'CWE-918': {
                'guidance': (
                    "SSRF Remediation:\n"
                    "1. Validate and whitelist allowed URLs/domains\n"
                    "2. Disable redirects in HTTP clients\n"
                    "3. Use network segmentation to limit internal access\n"
                    "4. Implement URL parsing and validation\n"
                    "5. Block requests to private IP ranges"
                ),
                'code_example': '''# Vulnerable code:
response = requests.get(user_url)

# Secure code:
from urllib.parse import urlparse
allowed_domains = ['api.example.com']
parsed = urlparse(user_url)
if parsed.netloc not in allowed_domains:
    raise ValueError("Invalid domain")
response = requests.get(user_url, allow_redirects=False)'''
            }
        }
