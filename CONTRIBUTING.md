# Contributing to Log Analyzer

Thank you for your interest in contributing to Log Analyzer! We welcome contributions in the form of bug reports, feature requests, code improvements, and documentation enhancements.

## How to Contribute

We welcome contributions in the form of:

- **Bug reports** - File issues for bugs you encounter
- **Feature requests** - Suggest new features or improvements
- **Code contributions** - Submit pull requests with bug fixes or new features
- **Documentation improvements** - Help improve our docs and examples

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any questions or comments.

## Getting Started

1. **Fork the repository** and clone it locally
2. **Create a feature branch** from `main` for your changes
3. **Make your changes** following our coding guidelines
4. **Test your changes** thoroughly
5. **Submit a pull request** with a clear description of your changes

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git

### Setting Up Your Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/log_analyzer.git
cd log_analyzer

# Create a virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Coding Guidelines

### Python Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Use type hints where appropriate

### Code Quality

- **No hardcoded credentials** - Use environment variables or configuration files
- **Validate user inputs** - Sanitize all external inputs to prevent injection attacks
- **Handle errors gracefully** - Use try-except blocks with appropriate error messages
- **Log appropriately** - Don't log sensitive information (passwords, keys, etc.)
- **Comment complex logic** - Help others understand your code

### Security Best Practices

- **Encrypt sensitive data** - Don't store passwords in plain text
- **Sanitize file paths** - Prevent path traversal vulnerabilities
- **Validate subprocess commands** - Use proper escaping for shell commands
- **Avoid security vulnerabilities** - Be cautious with external inputs and dependencies

## Pull Request Process

1. **Update documentation** - If you change functionality, update relevant docs
2. **Add tests** - Include tests for new features or bug fixes when applicable
3. **Keep PRs focused** - One feature/fix per pull request
4. **Write clear commit messages** - Explain what and why, not just what
5. **Link related issues** - Reference issue numbers in your PR description

### PR Title Format

Use clear, descriptive titles:

- `Fix: Resolve issue with log parsing`
- `Feature: Add support for custom log formats`
- `Docs: Update README with examples`
- `Refactor: Improve performance of log filtering`

### PR Description Template

```markdown
## Description

Brief description of what this PR does

## Related Issues

Fixes #123

## Changes Made

- Change 1
- Change 2

## Testing Done

- Test scenario 1
- Test scenario 2

## Additional Notes (if any)
```

## Reporting Issues

When filing an issue, please include:

- **Clear title** - Summarize the problem
- **Environment** - OS version, Python version, etc.
- **Steps to reproduce** - How to trigger the issue
- **Expected behavior** - What should happen
- **Actual behavior** - What actually happens
- **Error messages** - Include full error traces if available
- **Sample log file** - If applicable, include a sanitized sample log file

## Feature Requests

For feature requests, please describe:

- **Use case** - What problem does this solve?
- **Proposed solution** - How should it work?
- **Alternatives considered** - Other approaches you've thought about
- **Additional context** - Any other relevant information

## Code Review Process

- Maintainers will review PRs as time permits
- Address review feedback promptly
- PRs may be closed if inactive for 30 days
- At least one approving review required from a maintainer

## Questions?

If you have questions about contributing, feel free to:

- Open an issue in the repository
- Open a discussion in the repository
- Check existing issues and discussions for similar questions

## License

By contributing to Log Analyzer, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE) for details).

Thank you for contributing to Log Analyzer! 🎉
