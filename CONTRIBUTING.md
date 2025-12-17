# Contributing to AI-Driven DevSecOps Pipeline

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Screenshots if applicable

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues first
- Provide clear use case
- Explain expected behavior
- Consider implementation complexity

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests if applicable
   - Update documentation

4. **Test your changes**
   ```bash
   # Run AI engine tests
   cd ai-engine
   python -m pytest

   # Test dashboard
   cd dashboard
   npm run build
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: Add new feature description"
   ```
   
   Use conventional commits:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation
   - `refactor:` Code refactoring
   - `test:` Tests
   - `chore:` Maintenance

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📋 Development Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git

### Local Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Ai-Driven-DevSecOps-Pipeline
cd Ai-Driven-DevSecOps-Pipeline

# Install AI engine dependencies
cd ai-engine
pip install -r requirements.txt

# Install dashboard dependencies
cd ../dashboard
npm install
```

## 🎨 Code Style

### Python
- Follow PEP 8
- Use type hints
- Add docstrings for functions/classes
- Maximum line length: 100 characters

### JavaScript/React
- Use ES6+ syntax
- Follow Airbnb style guide
- Use functional components with hooks
- Add PropTypes or TypeScript

### YAML
- 2-space indentation
- Clear comments for complex configurations

## ✅ Testing

### AI Engine
```bash
cd ai-engine
python -m pytest tests/
```

### Dashboard
```bash
cd dashboard
npm test
```

### Integration Tests
Run the full pipeline locally before submitting PR.

## 📝 Documentation

- Update README.md if adding features
- Add inline code comments for complex logic
- Update CHANGELOG.md
- Include examples in documentation

## 🔒 Security

- Never commit secrets or API keys
- Report security vulnerabilities privately
- Follow secure coding practices
- Test security implications of changes

## 📞 Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review closed issues

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to making security automation better!** 🚀
