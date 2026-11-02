---
name: False positive
about: ActionGuard reported an action that is actually safe
labels: false-positive
---

**Verdict reported:** flagged / weak_guard

**Why it is safe** (public on purpose, a guard the scanner missed, not reachable, ...):

**A minimal snippet that reproduces it** (strip anything private; please don't paste a real
project's unpatched code):

```ts
"use server"
```

**ActionGuard version** (`npx @kobahiro/actionguard --help` or the action tag):
