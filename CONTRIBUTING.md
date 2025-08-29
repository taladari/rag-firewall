# Contributing to RAG Integrity Firewall

Thank you for your interest in contributing!  
We welcome bug reports, feature requests, new scanners, policy examples, and integrations with other frameworks.

---

## Ways to contribute

- **Bug reports:** Open an issue with clear steps to reproduce.  
- **Feature requests:** Suggest enhancements or new scanners in [GitHub Issues](https://github.com/taladari/rag-firewall/issues).  
- **Code contributions:** Submit a pull request (PR).  
- **Docs/examples:** Improve the README, examples, or add tutorials.  

---

## Development setup

1. Fork and clone the repo:
   ```bash
   git clone https://github.com/<your-fork>/rag-firewall.git
   cd rag-firewall
   ```

2. Install in editable mode:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e .
   pip install -r requirements-dev.txt
   ```

3. Run the test suite:
   ```bash
   pytest -q
   ```

---

## Coding guidelines

- Follow existing project style (PEP8, docstrings for public methods).  
- Add unit tests for new functionality (`tests/`).  
- Keep scanners modular (one file per scanner under `rag_firewall/scanners/`).  
- Include example usage if adding a new integration or CLI command.  

---

## Security issues

If you discover a security vulnerability, please **do not file a public issue**.  
Instead, email us at **talbuilds0@gmail.com**.
We will respond promptly and coordinate a fix.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and enterprise enhancements.

---

Thanks for helping improve RAG Integrity Firewall!
