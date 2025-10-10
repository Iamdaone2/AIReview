# AIReview 🔍

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**AIReview** is an intelligent Python code analysis tool that acts as your personal code reviewer. It performs comprehensive static analysis to identify **security vulnerabilities**, **performance bottlenecks**, **style violations**, and **potential bugs** in your Python projects.

 **Perfect for**: Code reviews, CI/CD pipelines, learning best practices, and maintaining high-quality codebases.

## Features

| Category | What It Catches | Impact |

| **Security** | `eval()` usage, hardcoded secrets, shell injection risks | **Critical** - Prevents security breaches |
| **Performance** | Nested loops, inefficient patterns, comprehensions | **High** - Improves application speed |
| **Style** | Naming conventions, missing docstrings, analysis complexity | **Medium** - Enhances code maintainability |
| **Bug Detection** | typos, incorrect comparisons, logic errors | **High** - Prevents runtime failures |

## Quick Start

### Prerequisites
- Python 3.8+ installed

### Installation

```bash
# Clone the repository
git clone https://github.com/Iamdaone2/AIReview.git
cd AIReview

# Verify Python version
python --version

# Test the installation
python Review.py --help
```

### Basic Usage

```bash
# Analyze a single file
python Review.py --file script.py

# Analyze entire project or folder
python Review.py --directory .

# Focus on critical issues only
python Review.py --directory . --severity high

# Save detailed report
python Review.py --directory . --output report.json
```

## Output Formats

### Table Format (Default)
```bash
python Review.py --directory . --format table
```
Perfect for terminal viewing with detailed issue breakdown.

### Summary Format
```bash
python Review.py --directory . --format summary
```
Great for quick overviews and CI/CD status checks.

### JSON Format
```bash
python Review.py --directory . --format json
```
Ideal for automation and integration with other tools.

## Advanced Usage

### Filter by Issue Type
```bash
# Security focused analysis
python Review.py --directory . --category security

# Performance optimization
python Review.py --directory . --category performance

# Style guide enforcement
python Review.py --directory . --category style
```

### Severity Filtering
```bash
# Only show critical and high severity issues
python Review.py --directory . --severity high

# Include medium priority issues
python Review.py --directory . --severity medium
```

### CI/CD Integration
```bash
# Generate report for continuous integration
python Review.py --directory . --format json --output ci_report.json --severity high

# Quick quality gate check
python Review.py --directory . --format summary | grep "Quality Score"
```

## Example Output

```yaml
🔍 Code Analysis Summary
==================================================
Files analyzed: 12
Total issues: 23
Quality Score: 87/100

Issues by Severity:
  🚨 Critical: 1
  ⚠️ High: 3
  🟠 Medium: 8
  💡 Low: 11

Issues by Category:
  🔒 Security: 2
  ⚡ Performance: 5
  🎨 Style: 12
  🐛 Bug: 4
 Detailed Issues
================================================================================

📄 src/main.py
--------------
🚨 Line 45:8 🔒 [CRITICAL] Using eval() can execute arbitrary code - security risk
    Code: result = eval(user_input)
    💡 Consider safer alternatives to eval()

⚠️ Line 67:12 ⚡ [HIGH] Deeply nested loop (depth: 3)
    Code: for item in nested_list:
    💡 Consider refactoring to reduce complexity
```

## What AIReview Detects

### Security Vulnerabilities
- Dangerous function calls (`eval`, `exec`, `compile`)
- Hardcoded passwords and API keys
- Shell injection risks in subprocess calls
- Unsafe dynamic imports

### Performance Issues
- Nested loop complexity (O(n³) and higher)
- Inefficient list operations in loops
- Complex list comprehensions
- Algorithmic bottlenecks

### Code Style & Quality
- Function naming conventions (snake_case)
- Missing docstrings
- Cyclomatic complexity analysis
- Code organization best practices

### Bug Prevention
- Common typos in built-in functions
- Incorrect comparison operators (`is` vs `==`)
- Logic errors and anti-patterns
- Undefined variable usage


### Development Setup
```bash
git clone https://github.com/Iamdaone2/AIReview.git
cd AIReview
# Create your feature branch
git checkout -b feature/amazing-feature
# Make your changes and test
python Review.py --directory . --format summary
# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made for the Python community**

*Happy coding and secure reviewing!* 
