# Rules Editor Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the raw-JSON-textarea rules editor with a card-based UI where each rule is a separate card with toggle, inline JSON edit, add/delete/search.

**Architecture:** All changes in a single file (`apps/electron/src/renderer/index.html`). IPC channels, preload bridge, and main process unchanged. The new modal HTML replaces the old one; the new JS replaces the old rules management logic.

**Tech Stack:** Vanilla JS (no framework), inline HTML/CSS, Electron preload bridge for IPC.

---

### Task 1: Replace modal HTML with card-based structure

**Files:**
- Modify: `apps/electron/src/renderer/index.html` (lines ~373-384)

- [ ] **Step 1: Remove old rules-modal div**

Delete lines 373-384 (the current `#rules-modal` div containing the textarea, Cancel/Save buttons).

- [ ] **Step 2: Add new rules-modal HTML**

Insert this after `</main>` (replacing the removed lines):

```html
    <div id="rules-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:999;align-items:center;justify-content:center;">
      <div style="background:#fff;border-radius:10px;padding:22px;max-width:750px;width:94%;max-height:90vh;display:flex;flex-direction:column;">
        <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
          <h2 style="margin:0">Custom Rules</h2>
          <button id="rules-close-modal" class="secondary" style="font-size:18px;padding:2px 10px;">&times;</button>
        </div>
        <p class="muted" style="font-size:13px;margin-bottom:10px;">Manage custom rules. Disabled rules are skipped during scan.</p>
        <div class="row" style="gap:8px;margin-bottom:10px;">
          <input id="rules-filter" type="text" placeholder="Filter rules..." style="flex:1;" />
          <button id="rules-add">+ Add Rule</button>
        </div>
        <div id="rules-list" style="flex:1;overflow-y:auto;min-height:200px;max-height:50vh;display:flex;flex-direction:column;gap:6px;">
          <div class="muted" style="text-align:center;padding:30px 0;">No custom rules yet. Click + Add Rule to create one.</div>
        </div>
        <div class="row" style="justify-content:space-between;align-items:center;margin-top:8px;padding-top:8px;border-top:1px solid #d9dee7;">
          <span id="rules-status" class="hint" style="flex:1;"></span>
          <span class="muted" id="rules-count" style="font-size:12px;"></span>
        </div>
      </div>
    </div>
```

- [ ] **Step 3: Add CSS for rules cards**

Add to the existing `<style>` block (before `@media`):

```css
      .rule-card {
        background:#fff;
        border:1px solid #d9dee7;
        border-radius:6px;
        padding:10px 12px;
        transition:border-color 0.15s;
      }
      .rule-card:hover {
        border-color:#1f6feb;
      }
      .rule-card-header {
        display:flex;
        align-items:center;
        gap:8px;
        cursor:pointer;
      }
      .rule-card-header .name {
        font-weight:600;
        flex:1;
      }
      .rule-card-header .badge {
        display:inline-block;
        color:#fff;
        padding:1px 8px;
        border-radius:3px;
        font-size:11px;
        font-weight:600;
        white-space:nowrap;
      }
      .rule-card-header .actions {
        display:flex;
        gap:4px;
        flex-shrink:0;
      }
      .rule-card .summary {
        font-size:12px;
        color:#667586;
        margin-top:4px;
        margin-left:28px;
      }
      .rule-card .edit-area {
        margin-top:8px;
        margin-left:28px;
        display:none;
      }
      .rule-card.expanded .edit-area {
        display:block;
      }
      .rule-card .edit-area textarea {
        width:100%;
        min-height:120px;
        font-family:monospace;
        font-size:12px;
        padding:8px;
        border:1px solid #d9dee7;
        border-radius:4px;
        resize:vertical;
        box-sizing:border-box;
      }
      .rule-card .edit-actions {
        display:flex;
        gap:6px;
        margin-top:6px;
        justify-content:flex-end;
      }
      .rule-card .card-error {
        color:#d1242f;
        font-size:12px;
        margin-top:4px;
      }
      .toggle-switch {
        position:relative;
        width:32px;
        height:18px;
        flex-shrink:0;
        cursor:pointer;
      }
      .toggle-switch input {
        opacity:0;
        width:0;
        height:0;
      }
      .toggle-slider {
        position:absolute;
        inset:0;
        background:#d0d7de;
        border-radius:9px;
        transition:0.2s;
      }
      .toggle-slider::before {
        content:"";
        position:absolute;
        width:14px;
        height:14px;
        left:2px;
        bottom:2px;
        background:#fff;
        border-radius:50%;
        transition:0.2s;
      }
      .toggle-switch input:checked + .toggle-slider {
        background:#1f6feb;
      }
      .toggle-switch input:checked + .toggle-slider::before {
        transform:translateX(14px);
      }
      #rules-list:empty .muted {
        display:block;
      }
```

- [ ] **Step 4: Build**

Run: `npm run build` (or just `npm run build --workspace apps/electron`)

- [ ] **Step 5: Commit**

```bash
git add apps/electron/src/renderer/index.html
git commit -m "feat: replace rules editor modal with card-based HTML structure"
```

---

### Task 2: Add card management JS logic

**Files:**
- Modify: `apps/electron/src/renderer/index.html` (JS section)

- [ ] **Step 1: Find and remove old rules editor JS**

Remove lines around 922-968 (the old `edit-rules` click handler, `rules-cancel`, `rules-modal` click, `rules-save` click).

- [ ] **Step 2: Add new rules management JS**

Add this before the closing `</script>` tag:

```javascript
      // === Rule Editor ===
      let rulesData = [];
      let rulesDirty = false;

      function escapeHtml(s) {
        return (s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
      }

      function severityBadge(sev) {
        const colors = { Critical:"#dc3545", High:"#fd7e14", Medium:"#ffc107", Low:"#0dcaf0", Info:"#6c757d" };
        const textColors = { Medium:"#212529" };
        const bg = colors[sev] || "#6c757d";
        const tc = textColors[sev] || "#fff";
        return `<span class="badge" style="background:${bg};color:${tc}">${sev}</span>`;
      }

      function matchSummary(rule) {
        if (!rule.match || !rule.match.length) return "no conditions";
        return rule.match.map(m => `${m.field}: ${m.operator} "${m.value}"`).join("; ");
      }

      function makeTemplateRule() {
        return { name: "", severity: "Medium", match: [{ field: "file", operator: "contains", value: "" }], enabled: true };
      }

      function renderRules(rules) {
        const container = $("rules-list");
        const filter = ($("rules-filter").value || "").toLowerCase();
        const filtered = filter ? rules.filter(r => (r.name||"").toLowerCase().includes(filter) || (r.description||"").toLowerCase().includes(filter)) : rules;
        if (filtered.length === 0) {
          container.innerHTML = `<div class="muted" style="text-align:center;padding:30px 0;">${rules.length === 0 ? "No custom rules yet. Click + Add Rule to create one." : "No rules match the filter."}</div>`;
        } else {
          container.innerHTML = filtered.map((rule, idx) => {
            const realIdx = rules.indexOf(rule);
            const enabled = rule.enabled !== false;
            return `<div class="rule-card" data-index="${realIdx}">
              <div class="rule-card-header" onclick="toggleCard(this.closest('.rule-card'))">
                <label class="toggle-switch" onclick="event.stopPropagation()">
                  <input type="checkbox" ${enabled ? "checked" : ""} onchange="toggleRule(${realIdx}, this.checked)" />
                  <span class="toggle-slider"></span>
                </label>
                <span class="name">${escapeHtml(rule.name) || "<em>unnamed</em>"}</span>
                ${severityBadge(rule.severity)}
                <span class="actions">
                  <button class="secondary" onclick="event.stopPropagation();editCard(${realIdx})" style="font-size:12px;padding:2px 8px;">Edit</button>
                  <button class="secondary" onclick="event.stopPropagation();deleteCard(${realIdx})" style="font-size:12px;padding:2px 8px;color:#d1242f;">Delete</button>
                </span>
              </div>
              <div class="summary">${escapeHtml(matchSummary(rule))}</div>
              <div class="edit-area">
                <textarea id="rule-textarea-${realIdx}">${escapeHtml(JSON.stringify(rule, null, 2))}</textarea>
                <div id="rule-error-${realIdx}" class="card-error"></div>
                <div class="edit-actions">
                  <button class="secondary" onclick="cancelEdit(${realIdx})" style="font-size:12px;padding:2px 10px;">Cancel</button>
                  <button onclick="saveCard(${realIdx})" style="font-size:12px;padding:2px 10px;">Save</button>
                </div>
              </div>
            </div>`;
          }).join("");
        }
        $("rules-count").textContent = `${rules.length} rule${rules.length !== 1 ? "s" : ""}`;
      }

      function toggleCard(el) {
        el.classList.toggle("expanded");
      }

      function toggleRule(idx, enabled) {
        if (rulesData[idx]) {
          rulesData[idx].enabled = enabled;
          rulesDirty = true;
          $("rules-status").textContent = "Unsaved changes";
          $("rules-status").className = "hint";
        }
      }

      function editCard(idx) {
        const card = document.querySelector(`.rule-card[data-index="${idx}"]`);
        if (card) {
          card.classList.add("expanded");
          const ta = document.getElementById(`rule-textarea-${idx}`);
          if (ta) {
            ta.value = JSON.stringify(rulesData[idx], null, 2);
            ta.focus();
          }
        }
      }

      function cancelEdit(idx) {
        const card = document.querySelector(`.rule-card[data-index="${idx}"]`);
        if (card) card.classList.remove("expanded");
        const err = document.getElementById(`rule-error-${idx}`);
        if (err) err.textContent = "";
      }

      function saveCard(idx) {
        const ta = document.getElementById(`rule-textarea-${idx}`);
        const err = document.getElementById(`rule-error-${idx}`);
        if (!ta || !err) return;
        try {
          const parsed = JSON.parse(ta.value);
          if (typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Must be a JSON object, not array");
          if (typeof parsed.name !== "string") throw new Error("Missing required field: name (string)");
          if (!["Critical","High","Medium","Low","Info"].includes(parsed.severity)) throw new Error("severity must be one of: Critical, High, Medium, Low, Info");
          if (!Array.isArray(parsed.match)) throw new Error("Missing required field: match (array)");
          rulesData[idx] = parsed;
          rulesDirty = true;
          $("rules-status").textContent = "Unsaved changes";
          $("rules-status").className = "hint";
          renderRules(rulesData);
        } catch (e) {
          err.textContent = "Invalid: " + e.message;
        }
      }

      function deleteCard(idx) {
        if (!confirm("Delete this rule?")) return;
        rulesData.splice(idx, 1);
        rulesDirty = true;
        $("rules-status").textContent = "Unsaved changes";
        $("rules-status").className = "hint";
        renderRules(rulesData);
      }

      $("rules-add").addEventListener("click", () => {
        const tpl = makeTemplateRule();
        rulesData.push(tpl);
        rulesDirty = true;
        $("rules-status").textContent = "Unsaved changes";
        $("rules-status").className = "hint";
        renderRules(rulesData);
        // Auto-expand the new rule
        setTimeout(() => {
          const cards = document.querySelectorAll(".rule-card");
          const last = cards[cards.length - 1];
          if (last) last.classList.add("expanded");
          const ta = last?.querySelector("textarea");
          if (ta) ta.focus();
        }, 50);
      });

      // Load rules on modal open
      async function openRulesEditor() {
        const modal = $("rules-modal");
        modal.style.display = "flex";
        $("rules-status").textContent = "Loading...";
        $("rules-status").className = "hint";
        try {
          const rules = await window.repoAuditor.rulesLoad();
          rulesData = rules.length > 0 ? JSON.parse(JSON.stringify(rules)) : [makeTemplateRule()];
          rulesDirty = false;
          renderRules(rulesData);
          $("rules-status").textContent = "";
        } catch (e) {
          $("rules-status").textContent = "Load failed: " + (e.message || e);
          $("rules-status").className = "hint error";
          rulesData = [makeTemplateRule()];
          renderRules(rulesData);
        }
      }

      function closeRulesEditor() {
        if (rulesDirty && !confirm("You have unsaved changes. Discard them?")) return;
        $("rules-modal").style.display = "none";
        rulesDirty = false;
      }

      $("edit-rules").addEventListener("click", openRulesEditor);
      $("rules-close-modal").addEventListener("click", closeRulesEditor);
      $("rules-modal").addEventListener("click", (e) => {
        if (e.target === $("rules-modal")) closeRulesEditor();
      });

      $("rules-filter").addEventListener("input", () => {
        renderRules(rulesData);
      });

      // Keyboard shortcut: Enter in textarea saves; Escape cancels
      document.addEventListener("keydown", (e) => {
        if ($("rules-modal").style.display !== "flex") return;
        if (e.key === "Escape") {
          // Close any expanded card
          const expanded = document.querySelector(".rule-card.expanded");
          if (expanded) {
            const idx = parseInt(expanded.dataset.index);
            cancelEdit(idx);
            e.preventDefault();
          } else {
            closeRulesEditor();
          }
        }
      });

      // "Save All" is handled by a button in the modal footer (added in Step 4).
      // saveAllRules() calls ipc.rulesSave(rulesData) directly.
```

- [ ] **Step 3: Add Save All button to modal footer**

In the modal footer div (between the existing status and rules-count elements), add:

```html
          <button id="rules-save-all" class="primary">Save All</button>
```

- [ ] **Step 4: Add Save All click handler**

Add before "Keyboard shortcut" section:

```javascript
      async function saveAllRules() {
        const status = $("rules-status");
        status.textContent = "Saving...";
        status.className = "hint";
        try {
          await window.repoAuditor.rulesSave(rulesData);
          rulesDirty = false;
          status.textContent = "Saved successfully";
          status.className = "hint success";
        } catch (e) {
          status.textContent = "Save failed: " + (e.message || e);
          status.className = "hint error";
        }
      }

      $("rules-save-all").addEventListener("click", saveAllRules);
```

Also update `closeRulesEditor` to not save automatically (just check dirty state):

```javascript
      function closeRulesEditor() {
        if (rulesDirty && !confirm("You have unsaved changes. Discard them?")) return;
        $("rules-modal").style.display = "none";
        rulesDirty = false;
      }
```

- [ ] **Step 5: Build**

Run: `npm run build --workspace apps/electron`

- [ ] **Step 6: Commit**

```bash
git add apps/electron/src/renderer/index.html
git commit -m "feat: add card-based rules editor with add/edit/delete/toggle/filter"
```

---

### Task 3: Verify tests pass

**Files:**
- No code changes

- [ ] **Step 1: Run full test suite**

Run: `npm test`
Expected: All 79 tests pass (IPC tests verify format options, scan tests verify functionality — unchanged since we didn't touch IPC or scanner)

- [ ] **Step 2: Verify no typecheck errors**

Run: `npm run build`
Expected: Clean compilation across all workspaces

---

### Self-Review Checklist

**Spec coverage:**
- Card-based UI with per-rule display → Task 1 HTML + Task 2 JS (renderRules function creates cards)
- Enable/disable toggle → Task 2 JS (toggleRule function)
- Add rule → Task 2 JS (Add Rule button → push template → render)
- Delete rule → Task 2 JS (deleteCard with confirm)
- Edit rule (expand textarea) → Task 2 JS (editCard/cancelEdit/saveCard)
- Save All to file → Task 2 Step 4 (saveAllRules via ipc.rulesSave)
- Filter rules → Task 2 JS (input event → renderRules with filter)
- Validation → Task 2 JS (saveCard validates name, severity, match)
- Empty state → Task 2 JS (renderRules empty check)
- Unsaved changes guard → Task 2 JS (closeRulesEditor confirm)

**Placeholder scan:** No TBDs, TODOs, or incomplete sections.

**Type consistency:** All function names and data structures consistent.

**Test gap:** No dedicated test for the rules editor UI — acceptable since it's vanilla JS UI in index.html with no test framework. Existing IPC tests still pass.
