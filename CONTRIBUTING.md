# Contributing to Agent Bounty Attacker Personas

Thank you for your interest in contributing to the Agent Bounty Attacker Personas Library! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Adding New Personas](#adding-new-personas)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project is committed to providing a welcoming and inclusive environment for all contributors. We expect all participants to adhere to our code of conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize defensive security applications
- No malicious code or harmful content

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment
4. Create a branch for your changes
5. Make your changes and test them
6. Submit a pull request

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Git
- Internet connection (for downloading MITRE data)

### Installation

```bash
# Clone your fork
git clone https://github.com/yourusername/attacker-personas.git
cd attacker-personas

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

### Development Tools

We use several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **pytest**: Testing

Run all checks:
```bash
# Format code
black agent_bounty/
isort agent_bounty/

# Lint
flake8 agent_bounty/

# Type check
mypy agent_bounty/

# Test
pytest --cov=agent_bounty
```

## Contributing Guidelines

### Security First

- **Defensive Use Only**: All contributions must be for defensive security purposes
- **No Malicious Code**: Do not submit actual malware, exploits, or harmful code
- **Simulation Only**: Focus on simulation and testing capabilities
- **Responsible Disclosure**: Report security issues privately first

### Code Quality

- Follow PEP 8 style guidelines
- Add type hints to all functions
- Include comprehensive docstrings
- Write tests for new functionality
- Maintain >80% test coverage

### Documentation

- Update README.md for significant changes
- Add docstrings to all public methods
- Include usage examples
- Update INTEGRATION_GUIDE.md for new integration patterns

## Adding New Personas

### Pre-configured Personas

To add a new hand-tuned persona to `PERSONA_CONFIGS`:

1. Research the threat group thoroughly using public sources
2. Verify the group exists in MITRE ATT&CK
3. Add configuration to `persona_library.py`:

```python
'NewAPTGroup': {
    'sophistication_level': SophisticationLevel.HIGH,
    'stealth_preference': StealthLevel.BALANCED,
    'attack_speed': AttackSpeed.MODERATE,
    'target_industries': ['Industry1', 'Industry2'],
    'target_regions': ['Region1', 'Region2'],
    'motivations': ['motivation1', 'motivation2'],
    'description_override': 'Accurate description based on public research',
    # ... other parameters
}
```

4. Add tests in `test_persona_library.py`
5. Update documentation

### Persona Generator Improvements

To improve the automated persona generation:

1. Enhance behavioral inference algorithms in `persona_generator.py`
2. Add new industry/regional keyword mappings
3. Improve sophistication detection patterns
4. Add confidence scoring enhancements

### Integration Patterns

To add new integration patterns:

1. Add to `persona_adapter.py` or `migration_toolkit.py`
2. Create example in `examples/integration_examples.py`
3. Add to `INTEGRATION_GUIDE.md`
4. Include compatibility analysis

## Testing

### Test Categories

- **Unit Tests**: Test individual components
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agent_bounty --cov-report=html

# Run specific test file
pytest tests/attacker_personas/test_persona.py -v

# Run integration tests (requires network)
pytest tests/ -m integration

# Skip slow tests
pytest -m "not slow"
```

### Writing Tests

- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Include edge cases
- Test error conditions

Example test structure:
```python
def test_persona_loading_success():
    """Test successful persona loading."""
    # Arrange
    library = PersonaLibrary()

    # Act
    persona = library.get_persona("APT29")

    # Assert
    assert persona.name == "APT29"
    assert len(persona.techniques) > 0
```

## Submitting Changes

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write code following our guidelines
   - Add/update tests
   - Update documentation

3. **Test Thoroughly**
   ```bash
   # Run all checks
   black agent_bounty/
   isort agent_bounty/
   flake8 agent_bounty/
   mypy agent_bounty/
   pytest --cov=agent_bounty
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new APT persona with behavioral analysis"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

Use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

### Pull Request Guidelines

- **Clear Title**: Descriptive title explaining the change
- **Detailed Description**: Explain what, why, and how
- **Link Issues**: Reference related issues
- **Test Results**: Include test output
- **Screenshots**: For UI changes
- **Breaking Changes**: Clearly mark breaking changes

### Review Process

1. Automated checks must pass
2. Code review by maintainers
3. Security review for sensitive changes
4. Integration testing
5. Documentation review
6. Final approval and merge

## Types of Contributions

### Welcome Contributions

- **New Persona Configurations**: Well-researched APT groups
- **Integration Patterns**: New ways to connect with existing tools
- **Bug Fixes**: Fixes for issues and edge cases
- **Documentation**: Improvements to guides and examples
- **Test Coverage**: Additional tests and test scenarios
- **Performance Improvements**: Optimizations and efficiency gains

### High-Value Contributions

- **Behavioral Analysis**: Improved persona behavioral modeling
- **MITRE Integration**: Enhanced ATT&CK framework integration
- **Tool Compatibility**: Support for additional security tools
- **Regional Coverage**: Personas for underrepresented regions
- **Industry Focus**: Industry-specific threat modeling

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- GitHub contributors list
- Release notes for significant contributions

## Getting Help

- **Documentation**: Check README.md and INTEGRATION_GUIDE.md
- **Issues**: Search existing issues or create new ones
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact team@agentbounty.com for sensitive issues

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to Agent Bounty! Your contributions help make cybersecurity more proactive and effective.