---
name: Missed finding
about: ActionGuard passed an action that should have been reported
labels: false-negative
---

**What the action does wrong** (no auth check, check after the query, wrong ownership check, ...):

**A minimal snippet that reproduces it** (written from scratch or from your own code; don't
paste another project's unpatched code into a public issue):

```ts
"use server"
```

**Verdict ActionGuard gave:** guard_before_sink / no_tainted_sink / unreferenced / not listed

**ActionGuard version:**
