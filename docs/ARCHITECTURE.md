# Architecture Documentation

## System Overview

The AI-Driven DevSecOps Pipeline is built on a modular, scalable architecture designed for enterprise-level security automation. The system integrates seamlessly into GitHub Actions and processes security scan results through an intelligent AI engine.

## Component Architecture

### 1. CI/CD Integration Layer (GitHub Actions)

**Purpose**: Orchestrates the entire security scanning workflow

**Components**:
- Workflow triggers (push, PR, schedule)
- Parallel job execution for SAST and DAST
- Artifact management and retention
- Security gate enforcement

**Key Features**:
- Zero-configuration deployment
- Automatic execution on code changes
- Configurable security gates
- Comprehensive logging and reporting

### 2. Security Scanning Layer

#### SAST (Semgrep)
- **Custom rules**: 25+ security patterns covering OWASP Top 10
- **Community rules**: Additional coverage from Semgrep registry
- **Output**: Structured JSON with findings, metadata, and confidence scores

#### DAST (OWASP ZAP)
- **Baseline scan**: Quick passive + active scanning
- **API scan**: OpenAPI/Swagger support
- **Configuration**: Custom scan policies and authentication
- **Output**: JSON with alerts, risk levels, and evidence

### 3. AI Processing Engine

The core intelligence of the system, written in Python with a modular design.

#### 3.1 Parser Module (`parsers.py`)
- Normalizes SAST and DAST results into common format
- Maps tool-specific severities to standard levels
- Enriches findings with CWE and OWASP classifications
- Generates unique vulnerability IDs

#### 3.2 False Positive Detector (`false_positive_detector.py`)
- **File pattern matching**: Excludes test files, build artifacts
- **Code pattern analysis**: Detects security exception markers
- **Context awareness**: Identifies test code and examples
- **Confidence scoring**: Multi-factor FP probability calculation

**Algorithm**:
```
FP_Score = Average(
  FilePatternScore,
  CodePatternScore,
  ContextScore,
  ScannerConfidenceScore
)

if FP_Score >= threshold:
  mark_as_false_positive()
```

#### 3.3 Risk Scorer (`risk_scorer.py`)
- **Multi-factor scoring**: Weighted combination of 5 factors
- **Exploitability assessment**: Based on CWE and known exploits
- **Business impact**: Severity-based damage estimation
- **Exposure calculation**: Public vs internal attack surface
- **Compliance mapping**: OWASP, CWE, regulatory frameworks

**Formula**:
```
Risk_Score = 
  Severity × 0.30 +
  Exploitability × 0.25 +
  Business_Impact × 0.20 +
  Exposure × 0.15 +
  Compliance × 0.10
```

#### 3.4 Prioritizer (`prioritizer.py`)
- **Auto-priority rules**: Policy-based automatic prioritization
- **Risk-based ranking**: Sorts by priority and risk score
- **SLA assignment**: Based on priority and severity
- **Effort estimation**: LOW/MEDIUM/HIGH based on CWE

#### 3.5 Remediation Engine (`remediation_engine.py`)
- **Template-based guidance**: Pre-written remediation for common CWEs
- **Code examples**: Vulnerable vs secure code snippets
- **Best practices**: OWASP and industry standard references
- **Contextual advice**: Tailored to vulnerability type

#### 3.6 Policy Loader (`policy_loader.py`)
- **YAML parsing**: Loads and validates policy configuration
- **Schema validation**: Ensures policy correctness
- **Default fallbacks**: Graceful handling of missing config
- **Helper methods**: Easy access to policy rules

### 4. Policy Engine (`config/policy.yml`)

**Purpose**: Centralized configuration for security rules and thresholds

**Configurable Elements**:
- Severity weights and blocking rules
- False positive exclusion patterns
- Risk scoring factor weights
- Compliance framework mappings
- Remediation SLAs
- Custom security rules

**Benefits**:
- Organization-specific customization
- Version-controlled security policy
- No code changes required for policy updates
- Audit trail for policy changes

### 5. Data Layer

**Storage**: JSON files in GitHub Actions artifacts

**Data Models**:
- `Vulnerability`: Individual security finding
- `ScanResult`: Collection of vulnerabilities from a scan
- `AnalysisReport`: Complete AI analysis output
- `PolicyConfig`: Parsed policy configuration

**Retention**:
- Raw scan results: 30 days
- AI analysis: 90 days
- Complete scan packages: 90 days

### 6. Visualization Layer (React Dashboard)

**Technology Stack**:
- React 18 with hooks
- Material-UI for components
- Recharts for data visualization
- Vite for build tooling

**Features**:
- Real-time data loading
- Interactive filtering and search
- Severity distribution charts
- Source breakdown visualization
- CSV export functionality
- Responsive design

## Data Flow

```
1. Code Push → GitHub Actions Trigger
2. Parallel Execution:
   - SAST (Semgrep) → semgrep.json
   - DAST (OWASP ZAP) → zap_report.json
3. AI Engine Processing:
   - Parse results → Normalized vulnerabilities
   - Detect false positives → Filtered list
   - Calculate risk scores → Scored vulnerabilities
   - Prioritize → Ranked list
   - Generate remediation → Complete report
4. Output Generation:
   - ai_analysis.json → Artifact storage
   - Dashboard build → Static site
5. Security Gate:
   - Check blocking severities
   - Pass/Fail CI/CD pipeline
```

## Scalability Considerations

### Horizontal Scaling
- **Parallel scanning**: SAST and DAST run concurrently
- **Modular AI engine**: Each component can be scaled independently
- **Stateless processing**: No dependencies between runs

### Performance Optimization
- **Caching**: GitHub Actions caches dependencies
- **Incremental analysis**: Only scan changed files (future enhancement)
- **Async processing**: Non-blocking operations where possible

### Enterprise Features
- **Multi-repository support**: Same workflow across repos
- **Centralized policy**: Shared policy configuration
- **API integration**: RESTful API for external tools (future)
- **Database backend**: For historical analysis (future)

## Security Considerations

### Pipeline Security
- **Secrets management**: GitHub Secrets for sensitive data
- **Least privilege**: Minimal permissions for workflow
- **Isolated execution**: Containerized scanning tools
- **Audit logging**: Complete workflow history

### Data Privacy
- **No external transmission**: All processing in GitHub Actions
- **Artifact encryption**: GitHub-managed encryption at rest
- **Access control**: Repository-level permissions
- **Retention policies**: Automatic cleanup of old data

## Extensibility

### Adding New Scanners
1. Create parser in `parsers.py`
2. Add job to workflow
3. Update AI engine to process new format

### Custom Rules
1. Add Semgrep rules to `semgrep-rules/`
2. Configure ZAP policies in `zap/zap-config.yml`
3. Define custom rules in `config/policy.yml`

### ML Integration (Future)
- Replace rule-based FP detection with ML model
- Train on historical developer feedback
- Adaptive risk scoring based on patterns
- Predictive vulnerability analysis

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| CI/CD | GitHub Actions | Native integration, free for public repos |
| SAST | Semgrep | Fast, customizable, great Python support |
| DAST | OWASP ZAP | Industry standard, Docker support |
| AI Engine | Python | Rich ecosystem, easy to extend |
| Dashboard | React | Modern, performant, great UX |
| Config | YAML | Human-readable, version-controllable |
| Data Format | JSON | Universal, easy to parse |

## Deployment Models

### 1. GitHub Actions (Recommended)
- Fully automated
- No infrastructure required
- Free for public repos

### 2. Self-Hosted Runners
- More control over environment
- Faster execution
- Custom tooling support

### 3. Standalone Deployment
- Run AI engine independently
- Integrate with any CI/CD
- Custom data sources

## Monitoring and Observability

### Metrics Tracked
- Scan execution time
- False positive rate
- Vulnerability trends
- Remediation time
- Policy compliance

### Logging
- Workflow execution logs
- AI engine verbose output
- Error tracking and debugging
- Audit trail for decisions

## Future Architecture Enhancements

1. **Microservices**: Split AI engine into separate services
2. **Message Queue**: Async processing with RabbitMQ/Kafka
3. **Database**: PostgreSQL for historical data
4. **API Gateway**: RESTful API for integrations
5. **ML Pipeline**: Separate training and inference services
6. **Distributed Caching**: Redis for performance
7. **Observability**: Prometheus + Grafana monitoring
