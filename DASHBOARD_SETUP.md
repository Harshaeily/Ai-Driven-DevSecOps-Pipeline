# Dashboard Setup with GitHub Actions Results

## Quick Setup (5 minutes)

### Step 1: Download the AI Analysis Artifact

1. Go to your workflow run: https://github.com/renegade475/Ai-Driven-DevSecOps-Pipeline/actions
2. Click on the latest successful run ("Test: Verify AI engine CWE fix in GitHub Actions")
3. Scroll to **Artifacts** section
4. Download **`ai-analysis`** artifact
5. Extract the zip file - you'll get `ai_analysis.json`

### Step 2: Copy to Dashboard

```powershell
# Create the data directory if it doesn't exist
mkdir dashboard\public\data -Force

# Copy the downloaded file
# Replace the path below with where you extracted the artifact
copy "C:\Users\notan\Downloads\ai-analysis\ai_analysis.json" dashboard\public\data\ai_analysis.json
```

### Step 3: Start the Dashboard

```powershell
cd dashboard

# If you haven't installed dependencies yet:
npm install

# Start the dev server:
npm run dev
```

### Step 4: View in Browser

Open your browser to: **http://localhost:5173**

You should see:
- 📊 **58 Total Vulnerabilities**
- 🔴 **0 Critical**
- 🟠 **18 High Priority**
- 🟡 **39 Medium**
- 🟢 **1 Low**
- Beautiful charts and interactive table
- Filtering and search capabilities
- CSV export functionality

---

## Alternative: Use Local Results

If you want to use the results you generated locally earlier:

```powershell
# Copy your local analysis
copy results\ai_analysis.json dashboard\public\data\ai_analysis.json

cd dashboard
npm run dev
```

---

## Troubleshooting

### Issue: npm not found
**Solution**: Restart PowerShell or add Node.js to PATH (see `DASHBOARD_SETUP.md`)

### Issue: Port 5173 already in use
**Solution**: 
```powershell
# Kill the existing process
Get-Process -Name node | Stop-Process -Force

# Or use a different port
npm run dev -- --port 3000
```

### Issue: Dashboard shows "No data"
**Solution**: Make sure `ai_analysis.json` is in `dashboard/public/data/` directory

---

## Build for Production (Optional)

To create a static build you can deploy anywhere:

```powershell
cd dashboard
npm run build

# The built files will be in dashboard/dist/
# You can open dist/index.html directly in a browser
```

---

## Deploy to GitHub Pages (Optional)

1. Uncomment the deployment step in `.github/workflows/security-scan.yml`
2. Enable GitHub Pages in repository settings
3. Set source to `gh-pages` branch
4. Your dashboard will be at: `https://renegade475.github.io/Ai-Driven-DevSecOps-Pipeline/`

---

## What You'll See

The dashboard displays:

### Summary Cards
- Total findings before/after filtering
- False positive rate
- Critical + High count

### Interactive Charts
- Pie chart: Severity distribution
- Bar chart: Source (SAST vs DAST)

### Vulnerability Table
- ID, Title, Severity, Risk Score
- CWE, Location, SLA days
- Sortable columns
- Search and filter

### Features
- 🔍 Filter by severity and source
- 🔎 Search vulnerabilities
- 📥 Export to CSV
- 🎨 Beautiful dark theme with glassmorphism
- ⚡ Smooth animations

**Your dashboard is ready to impress for your presentation!** 🎓✨
