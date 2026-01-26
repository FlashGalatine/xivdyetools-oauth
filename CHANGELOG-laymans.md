# What's New in v2.3.5

*Released: January 26, 2026*

---

## Overview

This is a maintenance release focused on improving our development security practices. **No user-facing changes** - Discord and XIVAuth login work exactly the same!

---

## What Changed?

### Better Security Scanning

We added automated tools that scan our code before it's published to:
- Detect if any passwords or API keys were accidentally included in the code
- Check for known security vulnerabilities in the libraries we use

This helps keep your authentication data safe by catching potential issues before they reach production.

### Automated Dependency Updates

We set up Dependabot to automatically suggest updates for the libraries and tools we use. This means:
- Security patches get applied faster
- We stay current with bug fixes and improvements

---

## For Developers

If you're interested in the technical details, check out [CHANGELOG.md](./CHANGELOG.md) for the full breakdown.

---

*No action required on your part. Just keep logging in as usual!*
