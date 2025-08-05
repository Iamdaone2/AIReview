
import ast
import re
import sys
import json
import argparse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import subprocess
from collections import defaultdict, Counter

@dataclass
class CodeIssue:
    """Represents a code issue found during analysis"""
    severity: str  
    category: str  
    line: int
    column: int
    message: str
    suggestion: Optional[str] = None
    code_snippet: Optional[str] = None

class SecurityAnalyzer(ast.NodeVisitor):
    """Analyzes code for potential security vulnerabilities"""
    
    def __init__(self):
        self.issues = []
        self.current_line = 1
    
    def visit_Call(self, node: ast.Call) -> None:
        """Check for dangerous function calls"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            dangerous_funcs = {
                'eval': 'Using eval() can execute arbitrary code - security risk',
                'exec': 'Using exec() can execute arbitrary code - security risk',
                'compile': 'Using compile() with user input can be dangerous',
                '__import__': 'Dynamic imports can be security risks'
            }
            
            if func_name in dangerous_funcs:
                self.issues.append(CodeIssue(
                    severity='critical',
                    category='security',
                    line=node.lineno,
                    column=node.col_offset,
                    message=dangerous_funcs[func_name],
                    suggestion=f'Consider safer alternatives to {func_name}()'
                ))
        
        elif isinstance(node.func, ast.Attribute):
            # Check for subprocess with shell=True
            if (isinstance(node.func.value, ast.Name) and 
                node.func.value.id == 'subprocess' and
                node.func.attr in ['call', 'run', 'Popen']):
                
                for keyword in node.keywords:
                    if (keyword.arg == 'shell' and 
                        isinstance(keyword.value, ast.Constant) and 
                        keyword.value.value is True):
                        
                        self.issues.append(CodeIssue(
                            severity='high',
                            category='security',
                            line=node.lineno,
                            column=node.col_offset,
                            message='subprocess with shell=True can lead to shell injection',
                            suggestion='Use shell=False and pass command as list'
                        ))
        
        self.generic_visit(node)
    
    def visit_Str(self, node: ast.Str) -> None:
        """Check for hardcoded secrets"""
        patterns = {
            r'password\s*=\s*["\'][^"\']+["\']': 'Hardcoded password detected',
            r'api_key\s*=\s*["\'][^"\']+["\']': 'Hardcoded API key detected',
            r'secret\s*=\s*["\'][^"\']+["\']': 'Hardcoded secret detected',
        }
        
        for pattern, message in patterns.items():
            if re.search(pattern, node.s, re.IGNORECASE):
                self.issues.append(CodeIssue(
                    severity='high',
                    category='security',
                    line=node.lineno,
                    column=node.col_offset,
                    message=message,
                    suggestion='Use environment variables or secure config files'
                ))
        
        self.generic_visit(node)

class PerformanceAnalyzer(ast.NodeVisitor):
    """Analyzes code for performance issues"""
    
    def __init__(self):
        self.issues = []
        self.loop_depth = 0
    
    def visit_For(self, node: ast.For) -> None:
        """Check for nested loops and inefficient patterns"""
        self.loop_depth += 1
        
        if self.loop_depth >= 3:
            self.issues.append(CodeIssue(
                severity='medium',
                category='performance',
                line=node.lineno,
                column=node.col_offset,
                message=f'Deeply nested loop (depth: {self.loop_depth})',
                suggestion='Consider refactoring to reduce complexity'
            ))
        
        # Check for list.append() in loops
        for stmt in ast.walk(node):
            if (isinstance(stmt, ast.Call) and
                isinstance(stmt.func, ast.Attribute) and
                stmt.func.attr == 'append'):
                
                self.issues.append(CodeIssue(
                    severity='low',
                    category='performance',
                    line=stmt.lineno,
                    column=stmt.col_offset,
                    message='Consider list comprehension instead of append in loop',
                    suggestion='Use list comprehension for better performance'
                ))
        
        self.generic_visit(node)
        self.loop_depth -= 1
    
    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Check for complex list comprehensions"""
        # Count nested comprehensions
        nested_count = sum(1 for _ in ast.walk(node) if isinstance(_, ast.ListComp))
        
        if nested_count > 2:
            self.issues.append(CodeIssue(
                severity='medium',
                category='performance',
                line=node.lineno,
                column=node.col_offset,
                message='Complex nested list comprehension',
                suggestion='Consider breaking into multiple steps for readability'
            ))
        
        self.generic_visit(node)

class StyleAnalyzer(ast.NodeVisitor):
    """Analyzes code for style and best practice issues"""
    
    def __init__(self):
        self.issues = []
        self.function_complexity = {}
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function complexity and naming"""
        # Check function name convention
        if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
            self.issues.append(CodeIssue(
                severity='low',
                category='style',
                line=node.lineno,
                column=node.col_offset,
                message=f'Function name "{node.name}" should use snake_case',
                suggestion='Use lowercase with underscores'
            ))
        
        # Calculate cyclomatic complexity
        complexity = self._calculate_complexity(node)
        if complexity > 10:
            self.issues.append(CodeIssue(
                severity='medium',
                category='style',
                line=node.lineno,
                column=node.col_offset,
                message=f'High cyclomatic complexity: {complexity}',
                suggestion='Consider breaking function into smaller functions'
            ))
        
        # Check for missing docstring
        if not ast.get_docstring(node):
            self.issues.append(CodeIssue(
                severity='low',
                category='style',
                line=node.lineno,
                column=node.col_offset,
                message=f'Function "{node.name}" missing docstring',
                suggestion='Add descriptive docstring'
            ))
        
        self.generic_visit(node)
    
    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity

class BugAnalyzer(ast.NodeVisitor):
    """Analyzes code for potential bugs"""
    
    def __init__(self):
        self.issues = []
        self.variables = set()
    
    def visit_Name(self, node: ast.Name) -> None:
        """Track variable usage"""
        if isinstance(node.ctx, ast.Store):
            self.variables.add(node.id)
        elif isinstance(node.ctx, ast.Load) and node.id not in self.variables:
            # Check for common typos in built-ins
            builtin_typos = {
                'lenght': 'len',
                'pirnt': 'print',
                'ragne': 'range',
                'ture': 'True',
                'flase': 'False'
            }
            
            if node.id in builtin_typos:
                self.issues.append(CodeIssue(
                    severity='high',
                    category='bug',
                    line=node.lineno,
                    column=node.col_offset,
                    message=f'Possible typo: "{node.id}"',
                    suggestion=f'Did you mean "{builtin_typos[node.id]}"?'
                ))
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare) -> None:
        """Check for comparison issues"""
        # Check for is/== with literals
        for i, op in enumerate(node.ops):
            comparator = node.comparators[i]
            
            if (isinstance(op, ast.Is) and 
                isinstance(comparator, (ast.Constant, ast.Str, ast.Num))):
                
                self.issues.append(CodeIssue(
                    severity='medium',
                    category='bug',
                    line=node.lineno,
                    column=node.col_offset,
                    message='Using "is" with literal - use "==" instead',
                    suggestion='Use "==" for value comparison'
                ))
        
        self.generic_visit(node)

class CodeAnalyzer:
    """Main code analyzer that coordinates all analysis types"""
    
    def __init__(self):
        self.analyzers = [
            SecurityAnalyzer(),
            PerformanceAnalyzer(),
            StyleAnalyzer(),
            BugAnalyzer()
        ]
    
    def analyze_file(self, file_path: Path) -> List[CodeIssue]:
        """Analyze a single Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=str(file_path))
            all_issues = []
            
            for analyzer in self.analyzers:
                analyzer.visit(tree)
                all_issues.extend(analyzer.issues)
                # Reset for next file
                analyzer.issues = []
            
            # Add file context to issues
            lines = content.split('\n')
            for issue in all_issues:
                if 1 <= issue.line <= len(lines):
                    issue.code_snippet = lines[issue.line - 1].strip()
            
            return sorted(all_issues, key=lambda x: (x.line, x.column))
            
        except SyntaxError as e:
            return [CodeIssue(
                severity='critical',
                category='bug',
                line=e.lineno or 1,
                column=e.offset or 0,
                message=f'Syntax error: {e.msg}',
                suggestion='Fix syntax error before analysis'
            )]
        except Exception as e:
            return [CodeIssue(
                severity='critical',
                category='bug',
                line=1,
                column=0,
                message=f'Analysis error: {str(e)}',
                suggestion='Check file format and permissions'
            )]
    
    def analyze_directory(self, dir_path: Path) -> Dict[str, List[CodeIssue]]:
        """Analyze all Python files in a directory"""
        results = {}
        
        for py_file in dir_path.rglob('*.py'):
            if not any(part.startswith('.') for part in py_file.parts):
                results[str(py_file)] = self.analyze_file(py_file)
        
        return results
    
    def generate_report(self, results: Dict[str, List[CodeIssue]]) -> Dict[str, Any]:
        """Generate a comprehensive analysis report"""
        total_issues = sum(len(issues) for issues in results.values())
        severity_counts = Counter()
        category_counts = Counter()
        
        for issues in results.values():
            for issue in issues:
                severity_counts[issue.severity] += 1
                category_counts[issue.category] += 1
        
        # Calculate quality score (0-100)
        score_deductions = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 1
        }
        
        total_deduction = sum(
            severity_counts[sev] * deduction 
            for sev, deduction in score_deductions.items()
        )
        
        quality_score = max(0, 100 - total_deduction)
        
        return {
            'summary': {
                'total_files': len(results),
                'total_issues': total_issues,
                'quality_score': quality_score,
                'severity_breakdown': dict(severity_counts),
                'category_breakdown': dict(category_counts)
            },
            'files': {
                filename: [
                    {
                        'severity': issue.severity,
                        'category': issue.category,
                        'line': issue.line,
                        'column': issue.column,
                        'message': issue.message,
                        'suggestion': issue.suggestion,
                        'code_snippet': issue.code_snippet
                    }
                    for issue in issues
                ]
                for filename, issues in results.items()
            }
        }

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='AI-Powered Code Review Assistant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file script.py
  %(prog)s --directory ./my_project --output report.json
  %(prog)s --directory . --format table --severity high
        """
    )
    
    parser.add_argument('--file', '-f', type=Path,
                       help='Analyze a single Python file')
    parser.add_argument('--directory', '-d', type=Path,
                       help='Analyze all Python files in directory')
    parser.add_argument('--output', '-o', type=Path,
                       help='Save report to file (JSON format)')
    parser.add_argument('--format', choices=['json', 'table', 'summary'],
                       default='table', help='Output format')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                       help='Filter by minimum severity level')
    parser.add_argument('--category', choices=['security', 'performance', 'style', 'bug'],
                       help='Filter by issue category')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.error('Must specify either --file or --directory')
    
    analyzer = CodeAnalyzer()
    
    # Run analysis
    if args.file:
        results = {str(args.file): analyzer.analyze_file(args.file)}
    else:
        results = analyzer.analyze_directory(args.directory)
    
    # Filter results
    if args.severity or args.category:
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        min_severity = severity_order.get(args.severity, 3)
        
        filtered_results = {}
        for filename, issues in results.items():
            filtered_issues = [
                issue for issue in issues
                if (not args.severity or severity_order[issue.severity] <= min_severity) and
                   (not args.category or issue.category == args.category)
            ]
            if filtered_issues:
                filtered_results[filename] = filtered_issues
        results = filtered_results
    
    # Generate and output report
    report = analyzer.generate_report(results)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    
    if args.format == 'json':
        print(json.dumps(report, indent=2))
    elif args.format == 'summary':
        print_summary(report)
    else:  # table format
        print_table_report(report)

def print_summary(report: Dict[str, Any]) -> None:
    """Print a summary of the analysis"""
    summary = report['summary']
    
    print("🔍 Code Analysis Summary")
    print("=" * 50)
    print(f"Files analyzed: {summary['total_files']}")
    print(f"Total issues: {summary['total_issues']}")
    print(f"Quality Score: {summary['quality_score']}/100")
    
    if summary['severity_breakdown']:
        print("\nIssues by Severity:")
        for severity, count in summary['severity_breakdown'].items():
            emoji = {'critical': '🚨', 'high': '⚠️', 'medium': '🟠', 'low': '💡'}
            print(f"  {emoji.get(severity, '•')} {severity.capitalize()}: {count}")
    
    if summary['category_breakdown']:
        print("\nIssues by Category:")
        for category, count in summary['category_breakdown'].items():
            emoji = {'security': '🔒', 'performance': '⚡', 'style': '🎨', 'bug': '🐛'}
            print(f"  {emoji.get(category, '•')} {category.capitalize()}: {count}")

def print_table_report(report: Dict[str, Any]) -> None:
    """Print a detailed table report"""
    print_summary(report)
    
    if not report['files']:
        print("\n✅ No issues found!")
        return
    
    print("\n📋 Detailed Issues")
    print("=" * 80)
    
    for filename, issues in report['files'].items():
        if not issues:
            continue
            
        print(f"\n📄 {filename}")
        print("-" * len(filename))
        
        for issue in issues:
            severity_emoji = {
                'critical': '🚨',
                'high': '⚠️',
                'medium': '🟠',
                'low': '💡'
            }
            
            category_emoji = {
                'security': '🔒',
                'performance': '⚡',
                'style': '🎨',
                'bug': '🐛'
            }
            
            print(f"{severity_emoji.get(issue['severity'], '•')} "
                  f"Line {issue['line']}:{issue['column']} "
                  f"{category_emoji.get(issue['category'], '')} "
                  f"[{issue['severity'].upper()}] {issue['message']}")
            
            if issue['code_snippet']:
                print(f"    Code: {issue['code_snippet']}")
            
            if issue['suggestion']:
                print(f"    💡 {issue['suggestion']}")
            
            print()

if __name__ == '__main__':
    main()