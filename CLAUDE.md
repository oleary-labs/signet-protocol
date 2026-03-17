# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Claude Code Instructions

## Autonomy & Decision-Making

Proceed without asking for confirmation whenever possible. Bias toward action.
Make reasonable assumptions and state them after the fact rather than stopping to ask upfront.
If you hit an ambiguity on a small detail, pick the most sensible option and move on.
Only pause and check in when a decision is **irreversible** or **high-risk** (see below).

---

## Always Allowed (No Confirmation Needed)

These actions should be taken freely without prompting:

**Read-only operations — never ask:**
- Reading any file, directory, or config
- Searching and grepping the codebase
- Running linters, type-checkers, or static analysis
- Running tests (read-only test runs)
- Viewing git log, diff, status, blame
- Inspecting environment variables (non-secret)
- Web searches or fetching documentation

**Safe write operations — proceed without asking:**
- Creating or editing source files
- Installing dependencies (`npm install`, `pip install`, etc.)
- Creating new files, directories, or configs
- Running build scripts (`npm run build`, `make`, etc.)
- Executing non-destructive shell commands
- Writing or updating tests
- Reformatting or refactoring code

---

## Always Require Explicit Permission

**Stop and ask before doing any of the following:**

- `git commit` — never commit without approval
- `git push` — never push to any remote without approval
- Opening or merging pull requests
- Deleting files or directories
- Dropping or truncating databases or data
- Modifying environment variables in production configs
- Any action that affects external services or sends network requests with side effects (emails, webhooks, payments, etc.)
- Changing CI/CD pipelines or deployment configs

---

## Code Style & Conventions

- Follow existing patterns in the codebase — consistency over personal preference
- Don't introduce new dependencies without mentioning it
- Prefer editing existing files over creating new abstractions unless necessary
- Write tests for any non-trivial logic you add or change
- Leave code at least as clean as you found it

---

## How to Handle Uncertainty

- **Small ambiguity** (naming, minor structure): pick the best option, note your choice at the end
- **Medium ambiguity** (architecture, approach): state your assumption and proceed, flag it in your summary
- **Large ambiguity** (unclear requirements, missing context): ask one focused question before proceeding

---

## Task Completion

When finishing a task, always provide a brief summary of:
1. What you did
2. Any assumptions you made
3. Anything that requires a follow-up decision (especially commits, pushes, or destructive actions)