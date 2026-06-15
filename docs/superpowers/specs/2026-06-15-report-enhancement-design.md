# Report Enhancement — Phase 1 Design

## Overview

Add four new outputs to the scanner without changing existing scan logic:
1. **Trust Score** (0-100 numerical score with classification)
2. **Risk Matrix** (Category × RiskLevel pivot table)
3. **Attack Surface Summary** (inventory-derived counts)
4. **HTML Report** (self-contained single-page HTML)

All outputs derive from the existing `AuditReport` and `ProjectInventory` types. No new scanning logic is required for Phase 1.

---

## 1. Trust Score

### Calculation

Start at 100, subtract weighted penalties:

| Condition | Penalty |
|-----------|---------|
| Per Critical finding | -25 |
| Per High finding | -12 |
| Per Medium finding | -5 |
| Per Low finding | -1 |
| Decision is "Block" | -10 |
| Any exfiltration path (edge with `dataType: "credentials"` or `dataType: "sensitive"`) | -10 |

Clamp to 0-100.

### Classification

| Range | Label |
|-------|-------|
| 90-100 | Trusted |
| 75-89 | Generally Safe |
| 50-74 | Use With Caution |
| 25-49 | High Risk |
| 0-24 | Critical Risk |

### Implementation

New function `computeTrustScore(report: AuditReport): number` in a new file `packages/scanner-core/src/trustScore.ts`. Exported from `index.ts`.

i18n: label translations in the existing `i18n.ts` dictionary.

---

## 2. Risk Matrix

A text table (for CLI/Markdown) and an HTML `<table>` (for HTML report) showing findings count by category × risk level.

### Data Structure

```typescript
type RiskMatrix = Record<string, Record<string, number>>;
// e.g. { "command-injection": { "Critical": 1, "High": 0, ... } }
```

### Implementation

New function `buildRiskMatrix(findings: Finding[]): RiskMatrix` in `reporters.ts`.
New function `renderRiskMatrixText(matrix, t): string` for Markdown reports.
New function `renderRiskMatrixHtml(matrix, t): string` for HTML reports.

Columns: Critical | High | Medium | Low | None (always, even when 0).
Empty cells show `-` in text, `0` or `—` in HTML.

---

## 3. Attack Surface Summary

Aggregate inventory data into a summary table.

### Fields

| Category | Source |
|----------|--------|
| Network endpoints | `inventory.networkEndpoints` count |
| Command executions | `inventory.commandExecutions` count |
| Filesystem reads | `inventory.filesystemReads` count |
| Env vars accessed | `inventory.environmentVariables` count |
| Persistence | `inventory.persistenceIndicators` count |
| GitHub workflows | `inventory.githubWorkflowFiles` count |
| Electron IPC files | `inventory.electronIpcFiles` count |

### Implementation

New function `buildAttackSurface(inventory: ProjectInventory): AttackSurfaceEntry[]`.

```typescript
interface AttackSurfaceEntry {
  category: string;
  count: number;
  highlights: string[];
}
```

The `highlights` array shows the first 3 unique file paths or endpoint URLs as examples.

---

## 4. HTML Report

A self-contained HTML string with inline CSS. No external dependencies.

### Layout

```
┌──────────────────────────────────────────┐
│  🛡  Repository Security Audit Report    │
│  Target: <source>                        │
│  Trust Score: XX/100 — <label>           │
│  Decision: <decision>                    │
├──────────────────────────────────────────┤
│  Risk Matrix                             │
│  (pivot table)                           │
│                                          │
│  Attack Surface Summary                  │
│  (category × count table)                │
├──────────────────────────────────────────┤
│  Findings                                │
│  ┌──────────────────────────────────────┐│
│  │ 🔴 Critical — command-injection     ││
│  │ src/index.ts:13                     ││
│  │ exec(`curl https://...`)            ││
│  │ The code invokes shell execution... ││
│  │ Fix: Avoid shell execution...       ││
│  │ Tags: command-execution             ││
│  └──────────────────────────────────────┘│
│  ...                                     │
├──────────────────────────────────────────┤
│  Data Flow                               │
│  (nodes and edges as definition list)    │
├──────────────────────────────────────────┤
│  Final Verdict                           │
│  <enum text>                             │
│  Generated: <date>                       │
│  Tool: Repository Security Auditor v0.1.0│
└──────────────────────────────────────────┘
```

### Finding card color coding

| Risk Level | Border/Accent |
|------------|---------------|
| Critical   | `#d1242f` (red) |
| High       | `#d1242f` (red) |
| Medium     | `#bf8700` (amber) |
| Low        | `#1a7f37` (green) |
| Info       | `#667586` (gray) |

### Data Flow in HTML

Render a flat node/edge list as HTML `<ul>`. Include a Mermaid source block (`<pre><code>`) for users who want to paste into mermaid.live.

### Implementation

New function `renderHtmlReport(report: AuditReport, trustScore, matrix, attackSurface, lang): string` in `reporters.ts`.

The function returns a complete HTML document string with:
- `<style>` block with all CSS
- `<body>` with the full layout
- No JavaScript required
- i18n applied to all labels and text
- Proper `<meta charset="utf-8">` and viewport tag

---

## 5. Final Verdict

Derive from trust score + decision:

| Decision | Trust Score | Verdict |
|----------|-------------|---------|
| Pass | >= 75 | APPROVED |
| Pass | < 75 | APPROVED WITH CAUTION |
| Monitor | any | MANUAL REVIEW REQUIRED |
| Needs Review | any | MANUAL REVIEW REQUIRED |
| Block | any | BLOCK IMMEDIATELY |

New function `computeFinalVerdict(decision, trustScore): string`.

---

## 6. AuditReport Type Change

Add `attackSurface` to `AuditReport`:

```typescript
export interface AuditReport {
  target: ResolvedTarget;
  findings: Finding[];
  dataFlow: DataFlowGraph;
  risk: RiskAssessment;
  attackSurface: AttackSurfaceEntry[];  // NEW
  generatedAt: string;
  toolVersion: string;
}
```

`AttackSurfaceEntry`:

```typescript
export interface AttackSurfaceEntry {
  category: string;
  count: number;
  highlights: string[];
}
```

## 7. Integration

### Scan.ts changes

In `scanTarget()`, after `buildInventory`, compute attack surface and store in report:

```
inventory → buildAttackSurface(inventory) → report.attackSurface
```

After findings are generated, compute trust score:

```
report → computeTrustScore(report) → used in HTML render
```

Add `html` to `OutputFormat` type.

### Reporters.ts changes

New exports:
- `buildRiskMatrix(findings)`
- `renderRiskMatrixText(matrix, t)`
- `renderHtmlReport(report, trustScore, riskMatrixHtml, lang)`
- `attackSurface → renderAttackSurfaceText(entries, t)`
- `computeTrustScore(report)`
- `computeFinalVerdict(decision, trustScore)`

### Electron app changes

- Add "html" to output format checkboxes (default: checked)
- Export `report.html` alongside existing formats

---

## 7. i18n

Add keys to `i18n.ts`:

```typescript
trustScore: { en: "Trust Score", ... }
trustScoreLabel: { en: "Trusted", "Use With Caution", ... }
riskMatrix: { en: "Risk Matrix", ... }
attackSurface: { en: "Attack Surface Summary", ... }
finalVerdict: { en: "Final Verdict", ... }
verdictApproved: { en: "APPROVED", ... }
```

---

## 8. Files Changed

| File | Change |
|------|--------|
| `packages/scanner-core/src/trustScore.ts` | NEW — computeTrustScore, computeFinalVerdict |
| `packages/scanner-core/src/reporters.ts` | ADD — risk matrix, attack surface, HTML report |
| `packages/scanner-core/src/types.ts` | ADD — `html` to OutputFormat, new interfaces |
| `packages/scanner-core/src/i18n.ts` | ADD — new translation keys |
| `packages/scanner-core/src/index.ts` | ADD — export new functions |
| `packages/scanner-core/src/scan.ts` | ADD — compute trust score, pass to renders |
| `apps/electron/src/renderer/index.html` | ADD — html checkbox, html export |
| `apps/electron/tests/ipc.test.ts` | UPDATE — output formats list |

---

## Out of Scope for Phase 1

- PDF generation (Phase 4)
- Mermaid.js client-side rendering in HTML
- Interactive HTML features
- Any changes to scan logic or rules
