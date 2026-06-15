# Rules Editor Improvement — Design Spec

## Goal

Replace the current raw-JSON-textarea rules editor with a card-based UI where each rule is a separate card with on/off toggle, edit-in-place JSON, and basic management (add/delete/search).

## Background

Current editor is a single `<textarea>` showing the entire `RuleDefinition[]` array as JSON. Users must manually manage commas, brackets, and array syntax — error-prone for multi-rule setups.

## UI Layout

### Modal (replaces current)

```
┌─────────────────────────────────────────────────────┐
│  Custom Rules                               [Close] │
│                                                     │
│  ┌─────────────────────────────────────────────────┐│
│  │ 🔍 Filter rules...              [+ Add Rule]    ││
│  └─────────────────────────────────────────────────┘│
│                                                     │
│  ┌─ Rule Card (collapsed) ─────────────────────────┐│
│  │ [🔛] postinstall-execution   Critical       ⚠️   ││
│  │ pattern: *.json                                 ││
│  │ [Edit] [Delete]                                 ││
│  └─────────────────────────────────────────────────┘│
│                                                     │
│  ┌─ Rule Card (expanded) ──────────────────────────┐│
│  │ [🔛] secret-token-check    High            ⚠️    ││
│  │ pattern: *.{ts,js,py}                            ││
│  │                                                   ││
│  │ ┌──────────────────────────────────────────────┐ ││
│  │ │ { "name": "secret-token-check", ... }          ││
│  │ └──────────────────────────────────────────────┘ ││
│  │ [Save] [Cancel]                                  ││
│  └──────────────────────────────────────────────────┘│
│                                                     │
│  [Save All to File]                         1 rule  │
└─────────────────────────────────────────────────────┘
```

### Card States

| State | Shows |
|-------|-------|
| Collapsed | Toggle, name, severity badge, match summary, [Edit][Delete] |
| Expanded-edit | Same header + textarea with single-rule JSON, [Save][Cancel] |
| Add-new | Empty card with template JSON `{ "name": "", "severity": "Medium", "match": [] }` |

## Interaction

- **Open modal** → `ipc.rulesLoad()` → render cards for each rule
- **Toggle** → set `rule.enabled = !rule.enabled` → update card UI (without saving; saved on "Save All")
- **Edit** → pre-fill textarea with `JSON.stringify(rule, null, 2)`
- **Save card** → `JSON.parse(textarea.value)` → validate (must be object, must have name/severity/match) → update in-memory array → collapse card
- **Add** → append default template to array → expand as new card
- **Delete** → confirmation → remove from array → re-render
- **Save All** → `ipc.rulesSave(allRules)` → status feedback
- **Cancel** (modal close) → if unsaved changes exist → confirm discard

## Data Model

Same as existing `RuleDefinition` (in `packages/scanner-core/src/ruleTypes.ts`):

```typescript
interface RuleDefinition {
  name: string;
  description?: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  match: { field: string; operator: string; value: string | string[] }[];
  enabled?: boolean;
}
```

## Files Changed

- `apps/electron/src/renderer/index.html` — remove old rules-modal, replace with new modal HTML + JS
- `apps/electron/src/main.ts` — no changes needed (IPC channels unchanged)
- `apps/electron/src/preload.cjs` — no changes needed (bridge methods unchanged)

## Validation

- JSON.parse must succeed for each rule's textarea
- Result must be an object with `name` (string), `severity` (enum), `match` (array)
- Invalid: show error hint per-card, prevent Save All
- Empty state: no rules — show "No custom rules yet. Click + Add Rule to create one."

## Out of Scope (Phase B)

- Test rule against current scan results
- Built-in rule templates gallery
- Drag-to-reorder
- Import/export single rule
