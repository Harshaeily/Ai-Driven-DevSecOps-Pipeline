# Testing via GitHub Actions - Quick Guide

## Option 1: Push to GitHub (Recommended)

### Step 1: Initialize Git Repository
```bash
cd c:\Users\notan\Documents\GitHub\Ai-Driven-DevSecOps-Pipeline

# Initialize git if not already done
git init
git branch -M main
```

### Step 2: Create GitHub Repository
1. Go to https://github.com/new
2. Name it: `Ai-Driven-DevSecOps-Pipeline`
3. **Do NOT** initialize with README (we already have files)
4. Click "Create repository"

### Step 3: Push Code
```bash
# Add all files
git add .

# Commit
git commit -m "Initial commit: AI-Driven DevSecOps Pipeline"

# Add remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/Ai-Driven-DevSecOps-Pipeline.git

# Push
git push -u origin main
```

### Step 4: Watch the Workflow Run
1. Go to your repository on GitHub
2. Click the **Actions** tab
3. You should see the workflow "AI-Driven DevSecOps Pipeline" running
4. Click on it to see real-time logs

### Step 5: View Results
After the workflow completes (~5-10 minutes):
1. Click on the completed workflow run
2. Scroll down to **Artifacts** section
3. Download:
   - `semgrep-results` - Raw SAST findings
   - `ai-analysis` - Processed AI results
   - `dashboard-build` - Built dashboard
   - `complete-security-scan-X` - All results combined

---

## Option 2: Manual Trigger (No Code Push)

If you just want to test without pushing code:

### Step 1: Enable Workflow Dispatch
The workflow is already configured for manual triggers!

### Step 2: Trigger Manually
1. Go to **Actions** tab
2. Click "AI-Driven DevSecOps Pipeline" in the left sidebar
3. Click **Run workflow** button (top right)
4. Select branch: `main`
5. Click green **Run workflow** button

---

## Option 3: Test with Pull Request

### Step 1: Create a New Branch
```bash
git checkout -b test-security-scan
```

### Step 2: Make a Small Change
```bash
# Add a comment to the vulnerable app
echo "# Test change" >> Vulnerable_app/app.py
git add Vulnerable_app/app.py
git commit -m "Test: trigger security scan"
git push origin test-security-scan
```

### Step 3: Create Pull Request
1. Go to your repository on GitHub
2. Click **Pull requests** tab
3. Click **New pull request**
4. Select `test-security-scan` branch
5. Click **Create pull request**

The workflow will automatically run on the PR!

---

## What to Expect

### Workflow Jobs (Run in Parallel)
1. **SAST Scan** (~2-3 minutes)
   - Runs Semgrep with custom rules
   - Scans the vulnerable app
   - Uploads results

2. **DAST Scan** (~3-5 minutes)
   - Starts the vulnerable Flask app
   - Runs OWASP ZAP baseline scan
   - Uploads results

3. **AI Analysis** (~1-2 minutes)
   - Downloads SAST/DAST results
   - Runs AI processing engine
   - Generates analysis report
   - Checks security gate

4. **Dashboard Build** (~2-3 minutes)
   - Builds React dashboard
   - Uploads build artifacts

5. **Aggregate Results** (~30 seconds)
   - Combines all results
   - Creates final report

### Expected Results

When scanning the vulnerable application:

```
📊 Analysis Summary:
  Total findings: 40-50
  After filtering: 15-20
  False positive rate: 60-70%
  Critical: 2-3
  High: 4-6
  Medium: 6-8
  Low: 2-4
```

### Security Gate
The workflow will **FAIL** if critical vulnerabilities are found (this is intentional with the vulnerable app). You'll see:

```
❌ FAILED: Critical vulnerabilities found!
  Critical vulnerabilities: 2
  High vulnerabilities: 5
```

This demonstrates the security gate working correctly!

---

## Troubleshooting

### Issue: Workflow doesn't appear in Actions tab
**Solution**: Make sure you've pushed the `.github/workflows/security-scan.yml` file

### Issue: DAST scan fails
**Solution**: The vulnerable app might not start properly. Check the logs in the "Start Vulnerable Application" step

### Issue: No artifacts generated
**Solution**: Workflows must complete (even with failures) to upload artifacts. Check if jobs completed.

### Issue: Want to skip DAST for faster testing
**Solution**: Comment out the `dast_scan` job in `.github/workflows/security-scan.yml`:

```yaml
# Temporarily disable DAST for faster testing
# dast_scan:
#   name: Dynamic Analysis (DAST)
#   ...
```

---

## Viewing the Dashboard

### Option 1: Download and Open Locally
1. Download `dashboard-build` artifact
2. Extract the zip file
3. Open `index.html` in a browser

### Option 2: Deploy to GitHub Pages
Uncomment the deployment step in `.github/workflows/security-scan.yml`:

```yaml
- name: Deploy to GitHub Pages
  uses: peaceiris/actions-gh-pages@v3
  if: github.ref == 'refs/heads/main'
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    publish_dir: ./dashboard/dist
```

Then enable GitHub Pages:
1. Settings → Pages
2. Source: `gh-pages` branch
3. Visit: `https://YOUR_USERNAME.github.io/Ai-Driven-DevSecOps-Pipeline/`

---

## Quick Test Commands

```bash
# Check if git is initialized
git status

# View current remote
git remote -v

# Check if workflow file exists
ls .github/workflows/security-scan.yml

# View recent commits
git log --oneline -5

# Force trigger workflow (after push)
gh workflow run security-scan.yml
```

---

## Next Steps After First Run

1. ✅ Review the workflow logs
2. ✅ Download and examine artifacts
3. ✅ Check the AI analysis JSON
4. ✅ View the dashboard
5. ✅ Customize `config/policy.yml` if needed
6. ✅ Add to your actual projects!

**Happy Testing! 🚀**
