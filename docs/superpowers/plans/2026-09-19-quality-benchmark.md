# Quality Benchmark — Precision/Recall Implementation Plan

> **For agentic workers:** use superpowers:subagent-driven-development or executing-plans. Checkbox tasks.

**Goal:** Quantify scanner quality against hand-labeled ground truth: a new `repo-auditor bench` command runs a benchmark spec (cases with expected findings), matches actual vs expected, and reports precision / recall / F1 per case and aggregate.

**Architecture:**

- `packages/scanner-core/src/benchmark.ts` (pure, no I/O):
  - `BenchExpectation { category: string; filePath: string; lineStart?: number; lineEnd?: number }`
  - `BenchMatchResult { truePositives: Array<{ expectation: BenchExpectation; findingId: string }>; falsePositives: string[]; falseNegatives: BenchExpectation[] }`
  - `BenchMetrics { tp: number; fp: number; fn: number; precision: number; recall: number; f1: number }`
  - `matchFindings(actual: Finding[], expected: BenchExpectation[]): BenchMatchResult` — greedy match in expectation order: category equal AND filePath equal AND (expectation without lineStart matches file-level; with lineStart requires inclusive line-range overlap: `finding.lineStart <= expLineEnd && expLineStart <= finding.lineEnd`, expLineEnd defaults to lineStart, finding lineEnd defaults to lineStart). Each finding satisfies at most one expectation.
  - `computeMetrics(result): BenchMetrics` — `precision = tp + fp === 0 ? 1 : tp / (tp + fp)`; `recall = tp + fn === 0 ? 1 : tp / (tp + fn)`; `f1 = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall)` (vacuous-truth convention: nothing expected + nothing found = perfect).
- `packages/cli/src/bench.ts` + registration in `createProgram` (index.ts):
  - Spec file (JSON): `{ cases: [{ name, target, expected: BenchExpectation[] }] }` — `target` resolved relative to the spec file's directory.
  - Command: `repo-auditor bench --spec <path> --output <dir>` — per case: `scanTarget(target, { reviewMode: "full-audit", networkPolicy: "offline", outputFormats: ["json"] })` → `report.findings` → match → metrics; aggregate = summed tp/fp/fn → metrics. Writes `benchmark-report.json` + `benchmark-report.md` to the output dir; prints a console table; exit code 0 (measurement tool, not a gate).
- `benchmarks/benchmarks.json` — first hand-labeled spec:
  - `malicious-package` (5 expectations): postinstall-script @ package.json:1; supply-chain @ package.json:1; command-injection @ src/index.ts:13; network @ src/index.ts:9; network @ src/index.ts:13.
  - `benign-package` (0 expectations).
  - Expected result when run: malicious precision 1.0 / recall 1.0 / F1 1.0; benign vacuous-perfect (1.0/1.0/1.0).
- README "Quality Benchmark" section.

**Out of scope:** AI-augmented benchmark mode (measure reflection/prompt changes with a live provider) — follow-up once the deterministic baseline exists.

**Context:** repo root. vitest picks up `packages/**/*.test.ts`. CLI tests: `npx vitest run packages/cli`. scanner-core tests: `npx vitest run packages/scanner-core`.

---

### Task 1: `benchmark.ts` pure matching + metrics (TDD)
- [ ] Tests `packages/scanner-core/tests/benchmark.test.ts`: category+filePath match; line-overlap match (expectation :13-13 vs finding :12-14 overlaps; :13 vs :15 does not); file-level expectation (no lineStart) matches any line in the file; each finding satisfies at most one expectation; unmatched findings → falsePositives (ids); unmatched expectations → falseNegatives; metrics math incl. vacuous-truth (no expected + none found → 1/1/1), precision 0.5 case, F1 rounding untouched (raw number).
- [ ] Implement `benchmark.ts`; export `BenchExpectation`, `BenchMatchResult`, `BenchMetrics`, `matchFindings`, `computeMetrics` from `packages/scanner-core/src/index.ts`.
- [ ] `npx vitest run packages/scanner-core` green; typecheck clean. Commit `feat(scanner-core): add precision/recall benchmark matching and metrics`.

### Task 2: CLI `bench` command (TDD)
- [ ] Tests `packages/cli/tests/bench.test.ts`: spec loader resolves target relative to spec dir; invalid spec (no cases) throws; bench run on a temp-fixture (copy of a tiny malicious fixture) produces benchmark-report.json with per-case metrics + aggregate markdown contains "Precision"; benign-style case with 0 expected and 0 actual → vacuous 1/1/1; command registered: `createProgram().parseAsync(["bench", ...])` runs end-to-end with a temp output dir (use the io injection pattern `CliIo` from index.ts).
- [ ] Implement `packages/cli/src/bench.ts`; register `program.command("bench")` in `createProgram`; export nothing new from index.ts beyond the command.
- [ ] `npx vitest run packages/cli` green; typecheck clean. Commit `feat(cli): add bench command for precision/recall benchmarking`.

### Task 3: First hand-labeled benchmark spec
- [ ] `benchmarks/benchmarks.json` per the Architecture section (targets relative to the spec file: `../fixtures/malicious-package`, `../fixtures/benign-package`).
- [ ] Run `node packages/cli/dist/index.js bench --spec benchmarks/benchmarks.json --output /tmp/ocr-bench-run` after rebuild; expect malicious 1.0/1.0/1.0 and benign vacuous-perfect; commit `test(bench): add hand-labeled benchmark for malicious and benign fixtures`.

### Task 4: README + verification
- [ ] README "Quality Benchmark" section (spec format, command, metrics definitions, vacuous-truth note).
- [ ] Full gates: `npx vitest run packages apps`, typecheck workspaces, commit docs.
