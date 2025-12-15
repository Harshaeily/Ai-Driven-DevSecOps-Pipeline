# Deployment Guide

## Overview

This guide covers deploying the AI-Driven DevSecOps Pipeline in various environments.

## GitHub Actions Deployment (Recommended)

### Prerequisites
- GitHub repository
- Admin access to repository settings

### Steps

1. **Fork or clone the repository**
   ```bash
   git clone https://github.com/yourusername/Ai-Driven-DevSecOps-Pipeline.git
   cd Ai-Driven-DevSecOps-Pipeline
   ```

2. **Configure secrets** (if using DAST)
   ```bash
   # Set target URL for ZAP scanning
   gh secret set ZAP_TARGET --body "https://your-app-url.com"
   ```

3. **Customize policy** (optional)
   
   Edit `config/policy.yml` to match your organization's security requirements.

4. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial setup"
   git push origin main
   ```

5. **Verify workflow**
   
   Go to Actions tab → Select "AI-Driven DevSecOps Pipeline" → Check execution

### Workflow Configuration

The workflow runs on:
- **Push** to `main` or `develop` branches
- **Pull requests** to `main` or `develop`
- **Manual trigger** via workflow_dispatch
- **Schedule**: Daily at 2 AM UTC

To modify triggers, edit `.github/workflows/security-scan.yml`:

```yaml
on:
  push:
    branches: [ main, develop, staging ]  # Add your branches
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Modify schedule
```

## Self-Hosted Runner Deployment

For organizations requiring more control or faster execution.

### Setup Self-Hosted Runner

1. **Navigate to repository settings**
   - Settings → Actions → Runners → New self-hosted runner

2. **Follow GitHub's instructions** to install runner on your server

3. **Install dependencies** on runner machine:
   ```bash
   # Python
   sudo apt-get install python3.11 python3-pip
   
   # Node.js
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   
   # Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   ```

4. **Update workflow** to use self-hosted runner:
   ```yaml
   jobs:
     sast_scan:
       runs-on: self-hosted  # Change from ubuntu-latest
   ```

## Standalone Deployment

Run the AI engine independently of GitHub Actions.

### Local Installation

1. **Install Python dependencies**
   ```bash
   cd ai-engine
   pip install -r requirements.txt
   ```

2. **Run scans manually**
   ```bash
   # SAST
   pip install semgrep
   semgrep --config ../semgrep-rules/ --json > ../results/sast/semgrep.json
   
   # DAST
   docker run --rm -v $(pwd)/../results:/zap/wrk owasp/zap2docker-stable \
     zap-baseline.py -t http://target-url -J /zap/wrk/zap_report.json
   ```

3. **Run AI analysis**
   ```bash
   python main.py \
     --sast-results ../results/sast/ \
     --dast-results ../results/dast/ \
     --policy ../config/policy.yml \
     --output ../results/ai_analysis.json \
     --verbose
   ```

### Integration with Other CI/CD

#### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            parallel {
                stage('SAST') {
                    steps {
                        sh 'semgrep --config semgrep-rules/ --json > results/semgrep.json'
                    }
                }
                stage('DAST') {
                    steps {
                        sh 'docker run --rm -v $(pwd)/results:/zap/wrk owasp/zap2docker-stable zap-baseline.py -t $TARGET_URL -J /zap/wrk/zap_report.json'
                    }
                }
            }
        }
        stage('AI Analysis') {
            steps {
                sh 'cd ai-engine && python main.py --sast-results ../results/sast/ --dast-results ../results/dast/ --policy ../config/policy.yml --output ../results/ai_analysis.json'
            }
        }
    }
}
```

#### GitLab CI

```yaml
stages:
  - scan
  - analyze

sast_scan:
  stage: scan
  script:
    - pip install semgrep
    - semgrep --config semgrep-rules/ --json > results/semgrep.json
  artifacts:
    paths:
      - results/semgrep.json

dast_scan:
  stage: scan
  script:
    - docker run --rm -v $(pwd)/results:/zap/wrk owasp/zap2docker-stable zap-baseline.py -t $TARGET_URL -J /zap/wrk/zap_report.json
  artifacts:
    paths:
      - results/zap_report.json

ai_analysis:
  stage: analyze
  script:
    - cd ai-engine
    - pip install -r requirements.txt
    - python main.py --sast-results ../results/sast/ --dast-results ../results/dast/ --policy ../config/policy.yml --output ../results/ai_analysis.json
  artifacts:
    paths:
      - results/ai_analysis.json
```

## Dashboard Deployment

### Option 1: GitHub Pages

1. **Build dashboard**
   ```bash
   cd dashboard
   npm install
   npm run build
   ```

2. **Deploy to GitHub Pages**
   
   Uncomment the deployment step in `.github/workflows/security-scan.yml`:
   ```yaml
   - name: Deploy to GitHub Pages
     uses: peaceiris/actions-gh-pages@v3
     if: github.ref == 'refs/heads/main'
     with:
       github_token: ${{ secrets.GITHUB_TOKEN }}
       publish_dir: ./dashboard/dist
   ```

3. **Enable GitHub Pages**
   - Settings → Pages → Source: gh-pages branch

### Option 2: Static Hosting (Netlify, Vercel)

1. **Build dashboard**
   ```bash
   cd dashboard
   npm run build
   ```

2. **Deploy to Netlify**
   ```bash
   npm install -g netlify-cli
   netlify deploy --prod --dir=dist
   ```

### Option 3: Self-Hosted Web Server

1. **Build dashboard**
   ```bash
   cd dashboard
   npm run build
   ```

2. **Copy to web server**
   ```bash
   scp -r dist/* user@server:/var/www/html/devsecops-dashboard/
   ```

3. **Configure Nginx**
   ```nginx
   server {
       listen 80;
       server_name dashboard.example.com;
       root /var/www/html/devsecops-dashboard;
       index index.html;
       
       location / {
           try_files $uri $uri/ /index.html;
       }
   }
   ```

## Production Considerations

### Security

1. **Secrets Management**
   - Use GitHub Secrets for sensitive data
   - Rotate secrets regularly
   - Never commit secrets to repository

2. **Access Control**
   - Limit repository access
   - Use branch protection rules
   - Require code reviews for policy changes

3. **Audit Logging**
   - Enable GitHub audit log
   - Monitor workflow executions
   - Track policy modifications

### Performance

1. **Caching**
   - Enable dependency caching in workflows
   - Use Docker layer caching for ZAP

2. **Parallel Execution**
   - Keep SAST and DAST jobs parallel
   - Use matrix builds for multiple targets

3. **Resource Limits**
   - Set timeouts for long-running scans
   - Limit artifact retention period

### Monitoring

1. **Workflow Monitoring**
   - Set up notifications for failures
   - Track execution time trends
   - Monitor artifact storage usage

2. **Dashboard Analytics**
   - Track vulnerability trends
   - Monitor false positive rates
   - Measure remediation times

### Backup and Recovery

1. **Policy Backup**
   - Version control for `config/policy.yml`
   - Document policy changes

2. **Data Retention**
   - Archive important scan results
   - Export historical data periodically

## Troubleshooting

### Common Issues

**Workflow fails on SAST scan**
- Check Semgrep rules syntax
- Verify Python version (3.11+)
- Review error logs in Actions tab

**DAST scan times out**
- Increase timeout in workflow
- Reduce ZAP scan scope
- Check target application availability

**AI analysis fails**
- Verify policy.yml syntax
- Check Python dependencies
- Enable verbose logging

**Dashboard doesn't load data**
- Ensure ai_analysis.json exists in public/data/
- Check browser console for errors
- Verify JSON format

### Debug Mode

Enable verbose logging:

```bash
# AI Engine
python main.py --verbose ...

# Semgrep
semgrep --verbose ...

# ZAP
docker run ... zap-baseline.py -d ...
```

## Scaling for Enterprise

### Multi-Repository Setup

1. **Create shared policy repository**
2. **Reference policy in workflows**:
   ```yaml
   - name: Download shared policy
     run: |
       curl -o config/policy.yml https://raw.githubusercontent.com/org/security-policies/main/devsecops-policy.yml
   ```

### Centralized Reporting

1. **Set up central database**
2. **Modify AI engine to push results**
3. **Create aggregated dashboard**

### Custom Integrations

1. **JIRA integration** for ticket creation
2. **Slack notifications** for critical findings
3. **Email reports** for stakeholders

## Support

For deployment assistance:
- Review [Architecture Documentation](ARCHITECTURE.md)
- Check [GitHub Issues](https://github.com/yourusername/Ai-Driven-DevSecOps-Pipeline/issues)
- Contact: your.email@example.com
