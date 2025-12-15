# Getting Started with AI-Driven DevSecOps Pipeline

## Quick Setup (5 minutes)

### 1. Prerequisites Check
```bash
# Verify installations
python --version  # Should be 3.11+
node --version    # Should be 18+
docker --version  # For OWASP ZAP
```

### 2. Test the Vulnerable Application
```bash
cd Vulnerable_app
pip install -r requirements.txt
python app.py
```
Visit http://localhost:5000 to see the test application.

### 3. Run a Local Security Scan
```bash
# Install Semgrep
pip install semgrep

# Run SAST scan
mkdir -p results/sast
semgrep --config semgrep-rules/ --json > results/sast/semgrep.json

# You should see findings for SQL injection, XSS, hardcoded secrets, etc.
```

### 4. Run AI Analysis
```bash
cd ai-engine
pip install -r requirements.txt

# Create dummy DAST results for testing
mkdir -p ../results/dast
echo '{"site":[{"alerts":[]}]}' > ../results/dast/zap_report.json

# Run AI engine
python main.py \
  --sast-results ../results/sast/ \
  --dast-results ../results/dast/ \
  --policy ../config/policy.yml \
  --output ../results/ai_analysis.json \
  --verbose
```

You should see output like:
```
✅ AI Analysis completed successfully
📊 Analysis Summary:
  Total findings: 25
  After filtering: 10
  False positive rate: 60.0%
  Critical: 2
  High: 3
  Medium: 4
  Low: 1
```

### 5. View the Dashboard
```bash
cd dashboard
npm install
npm run dev
```
Visit http://localhost:5173 to see the dashboard.

## GitHub Actions Setup

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit: AI-Driven DevSecOps Pipeline"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Ai-Driven-DevSecOps-Pipeline.git
git push -u origin main
```

### 2. Configure Secrets (Optional for DAST)
```bash
# Set target URL for ZAP scanning
gh secret set ZAP_TARGET --body "http://your-test-app.com"
```

### 3. Trigger Workflow
The workflow will automatically run on:
- Every push to `main` or `develop`
- Every pull request
- Daily at 2 AM UTC
- Manual trigger from Actions tab

### 4. View Results
1. Go to **Actions** tab in GitHub
2. Click on the latest workflow run
3. Download artifacts:
   - `semgrep-results`: Raw SAST findings
   - `zap-results`: Raw DAST findings
   - `ai-analysis`: Processed results with AI insights
   - `dashboard-build`: Built dashboard

## Customization

### Adjust Security Policy
Edit `config/policy.yml`:

```yaml
# Example: Make the pipeline stricter
severity:
  blocking_severities:
    - CRITICAL
    - HIGH
    - MEDIUM  # Add MEDIUM to block on medium severity

# Example: Reduce false positive threshold
false_positive_detection:
  confidence_threshold: 0.8  # Increase from 0.7
```

### Add Custom Semgrep Rules
Edit `semgrep-rules/default.yml`:

```yaml
rules:
  - id: my-custom-rule
    patterns:
      - pattern: dangerous_function($X)
    message: "Avoid using dangerous_function"
    languages: [python]
    severity: ERROR
```

## Common Issues

**Q: Workflow fails with "No vulnerabilities found"**
A: This is normal if scanning a small/secure codebase. The vulnerable app is included for testing.

**Q: Dashboard shows "Failed to load data"**
A: Ensure `ai_analysis.json` exists in `dashboard/public/data/`. Copy it from workflow artifacts.

**Q: DAST scan times out**
A: Increase timeout in workflow or reduce ZAP scan scope in `zap/zap-config.yml`.

## Next Steps

1. ✅ Test locally with vulnerable app
2. ✅ Push to GitHub and verify workflow
3. ✅ Customize policy for your needs
4. ✅ Add to your actual projects
5. ✅ Present to your team/evaluators

## Support

- 📖 [Full Documentation](README.md)
- 🏗️ [Architecture Guide](docs/ARCHITECTURE.md)
- 🚀 [Deployment Guide](docs/DEPLOYMENT.md)
- 📝 [Walkthrough](walkthrough.md)

**Ready to make your software more secure!** 🔒
