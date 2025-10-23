# AIReview

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)


Code reviews, CI/CD pipelines, learning best practices, and maintaining high-quality codebases.

## Features

| Category | What It Catches | Impact |

| **Security** | `eval()` usage, hardcoded secrets, shell injection risks | **Critical** - Prevents security breaches |
| **Performance** | Nested loops, inefficient patterns, comprehensions | **High** - Improves application speed |
| **Style** | Naming conventions, missing docstrings, analysis complexity | **Medium** - Enhances code maintainability |
| **Bug Detection** | typos, incorrect comparisons, logic errors | **High** - Prevents runtime failures |

## Quick Start

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


## License

This project is licensed under the MIT License - [LICENSE](LICENSE) file for details.

---

**Made for the Python community**
