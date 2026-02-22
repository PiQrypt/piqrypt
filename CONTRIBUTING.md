# Contributing to PiQrypt

**Thank you for your interest in contributing!** 🎉

We welcome contributions of all kinds: bug fixes, features, documentation, examples, and more.

---

## 📋 Ways to Contribute

- 🐛 **Report bugs** ([GitHub Issues](https://github.com/piqrypt/piqrypt/issues))
- 💡 **Suggest features** ([GitHub Discussions](https://github.com/piqrypt/piqrypt/discussions))
- 📝 **Improve documentation**
- 🧪 **Add tests**
- 🔧 **Fix bugs**
- ✨ **Implement features**
- 📦 **Create examples**

---

## 🚀 Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/piqrypt
cd piqrypt
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
```

### 3. Install Development Dependencies

```bash
pip install -e .[dev]
```

**Dev dependencies include:**
- pytest (testing)
- black (code formatting)
- flake8 (linting)
- mypy (type checking)

### 4. Run Tests

```bash
pytest
```

**Expected output:**
```
======================== 32 passed in 2.34s ========================
```

---

## 🔧 Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-123
```

### 2. Make Changes

**Code style:**
- Follow PEP 8
- Use type hints
- Write docstrings (Google style)
- Add tests for new features

**Example:**
```python
def stamp_event(
    private_key: bytes,
    agent_id: str,
    payload: Dict[str, Any],
    previous_hash: Optional[str] = None
) -> Dict[str, Any]:
    """
    Sign an event with agent private key.
    
    Args:
        private_key: Ed25519 private key (32 bytes)
        agent_id: Agent identifier
        payload: Event payload (JSON-serializable dict)
        previous_hash: Hash of previous event (for chaining)
    
    Returns:
        Signed AISS-1.0 event dict
    
    Raises:
        ValueError: If payload not JSON-serializable
    
    Example:
        >>> event = stamp_event(priv_key, agent_id, {"action": "test"})
        >>> event["version"]
        'AISS-1.0'
    """
    # Implementation...
```

### 3. Format & Lint

```bash
# Format code
black .

# Lint
flake8 aiss/ cli/ tests/

# Type check
mypy aiss/
```

### 4. Add Tests

**Test file:** `tests/test_your_feature.py`

```python
import pytest
from aiss import stamp_event, generate_keypair

def test_stamp_event_basic():
    """Test basic event stamping."""
    priv, pub = generate_keypair()
    agent_id = derive_agent_id(pub)
    
    event = stamp_event(priv, agent_id, {"action": "test"})
    
    assert event["version"] == "AISS-1.0"
    assert event["agent_id"] == agent_id
    assert "signature" in event

def test_stamp_event_chain():
    """Test event chaining."""
    # ... test implementation
```

**Run your tests:**
```bash
pytest tests/test_your_feature.py -v
```

### 5. Commit Changes

**Commit message format:**
```
type(scope): Brief description

Longer explanation (optional)

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `chore`: Maintenance

**Examples:**
```bash
git commit -m "feat(crypto): Add Dilithium3 signature support"
git commit -m "fix(memory): Correct SQLite index offset calculation"
git commit -m "docs(readme): Update installation instructions"
```

### 6. Push & Pull Request

```bash
git push origin feature/your-feature-name
```

**Create PR on GitHub:**
- Clear title
- Description of changes
- Reference related issues
- Screenshots (if UI changes)

---

## 📚 Documentation

### Code Documentation

- **Docstrings:** All public functions/classes
- **Type hints:** All function parameters/returns
- **Examples:** In docstrings when helpful

### User Documentation

**Update when adding features:**
- `README.md` (if user-facing)
- `QUICK-START.md` (if workflow changes)
- `docs/RFC.md` (if protocol changes)
- `CHANGELOG.md` (always)

---

## 🧪 Testing Guidelines

### What to Test

- ✅ Happy path (normal usage)
- ✅ Edge cases (empty inputs, large inputs)
- ✅ Error cases (invalid inputs)
- ✅ Integration (multiple components)

### Test Coverage

**Target:** 80%+ coverage for new code

**Check coverage:**
```bash
pytest --cov=aiss --cov-report=html
open htmlcov/index.html
```

### Test Structure

```python
def test_feature_name():
    """One-line description of what's tested."""
    # Arrange
    setup_data = ...
    
    # Act
    result = function_under_test(setup_data)
    
    # Assert
    assert result == expected_value
```

---

## 🔒 Security

**If you find a security vulnerability:**

1. **DO NOT** open a public issue
2. Email: piqrypt@gmail.com
3. Subject: `[SECURITY] Vulnerability Report`
4. We'll respond within 24 hours

See [SECURITY.md](SECURITY.md) for details.

---

## 📋 Code Review Process

### What We Look For

- ✅ Tests passing
- ✅ Code style consistent
- ✅ Documentation updated
- ✅ No breaking changes (without discussion)
- ✅ Performance considerations
- ✅ Security implications addressed

### Timeline

- **Initial review:** Within 3 business days
- **Follow-up:** Within 2 business days
- **Merge:** When approved + CI passing

---

## 🏆 Recognition

**Contributors will be:**
- Added to `CONTRIBUTORS.md`
- Mentioned in release notes
- Thanked publicly (if desired)

**Top contributors may receive:**
- Free Pro license
- Contributor badge
- Feature naming rights
- Early access to new features

---

## 💬 Communication

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** Questions, ideas, help
- **Email:** piqrypt@gmail.com (general)
- **Discord:** (coming soon)

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## ❓ Questions?

**Not sure where to start?**
- Browse [good first issues](https://github.com/piqrypt/piqrypt/labels/good%20first%20issue)
- Ask in [Discussions](https://github.com/piqrypt/piqrypt/discussions)
- Email: piqrypt@gmail.com

**Thank you for making PiQrypt better!** 🙏

---

**Last updated:** 2026-02-19
