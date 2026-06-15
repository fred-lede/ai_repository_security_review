import type { Decision, FindingCategory, RiskLevel } from "./types.js";

export type Language = "en" | "zh-TW" | "zh-CN";

const riskLevelLabels: Record<Language, Record<RiskLevel, string>> = {
  en: { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", Info: "Info" },
  "zh-TW": { Critical: "嚴重風險", High: "高風險", Medium: "中風險", Low: "低風險", Info: "資訊" },
  "zh-CN": { Critical: "严重风险", High: "高风险", Medium: "中风险", Low: "低风险", Info: "信息" }
};

const decisionLabels: Record<Language, Record<Decision, string>> = {
  en: { Block: "Block", "Needs Review": "Needs Review", Monitor: "Monitor", Pass: "Pass" },
  "zh-TW": { Block: "阻擋", "Needs Review": "需要人工審查", Monitor: "監控", Pass: "通過" },
  "zh-CN": { Block: "阻挡", "Needs Review": "需要人工审查", Monitor: "监控", Pass: "通过" }
};

const categoryLabels: Record<Language, Record<FindingCategory, string>> = {
  en: {
    "data-exfiltration": "Data Exfiltration",
    "credential-leakage": "Credential Leakage",
    "hidden-telemetry": "Hidden Telemetry",
    tracking: "Tracking",
    "remote-code-execution": "Remote Code Execution",
    "command-injection": "Command Injection",
    "supply-chain": "Supply Chain Risk",
    "postinstall-script": "Postinstall Script",
    "github-actions": "GitHub Actions Risk",
    "electron-ipc": "Electron IPC Risk",
    persistence: "Persistence Mechanism",
    network: "Network Communication",
    filesystem: "Filesystem Access",
    environment: "Environment Variable Access",
    database: "Database Access"
  },
  "zh-TW": {
    "data-exfiltration": "資料外洩",
    "credential-leakage": "憑證洩漏",
    "hidden-telemetry": "隱藏遙測",
    tracking: "追蹤行為",
    "remote-code-execution": "遠端程式碼執行",
    "command-injection": "命令注入",
    "supply-chain": "供應鏈風險",
    "postinstall-script": "安裝後腳本",
    "github-actions": "GitHub Actions 風險",
    "electron-ipc": "Electron IPC 風險",
    persistence: "持久化機制",
    network: "網路通訊",
    filesystem: "檔案系統存取",
    environment: "環境變數存取",
    database: "資料庫存取"
  },
  "zh-CN": {
    "data-exfiltration": "数据泄露",
    "credential-leakage": "凭证泄露",
    "hidden-telemetry": "隐藏遥测",
    tracking: "追踪行为",
    "remote-code-execution": "远程代码执行",
    "command-injection": "命令注入",
    "supply-chain": "供应链风险",
    "postinstall-script": "安装后脚本",
    "github-actions": "GitHub Actions 风险",
    "electron-ipc": "Electron IPC 风险",
    persistence: "持久化机制",
    network: "网络通信",
    filesystem: "文件系统访问",
    environment: "环境变量访问",
    database: "数据库访问"
  }
};

const reportStrings: Record<Language, Record<string, string>> = {
  en: {
    "report.title": "Repository Security Audit Report",
    "report.summary": "Executive Summary",
    "report.riskLevel": "Overall Risk Level",
    "report.decision": "Decision",
    "report.rationale": "Rationale",
    "report.scope": "Scan Scope",
    "report.target": "Target",
    "report.targetType": "Target Type",
    "report.networkUsed": "Network Used During Acquisition",
    "report.generatedAt": "Generated At",
    "report.findings": "Findings",
    "report.dataFlow": "Data Flow",
    "report.remediation": "Remediation Suggestions",
    "report.codeSnippet": "Code Snippet",
    "report.explanation": "Explanation",
    "report.recommendedFix": "Recommended Fix",
    "report.riskLevelLabel": "Risk Level",
    "report.filePath": "File Path",
    "report.confidence": "Confidence",
    "report.yes": "Yes",
    "report.no": "No",
    "trustScore": "Trust Score",
    "trustScoreLabel": "Trusted",
    "trustScoreGenerallySafe": "Generally Safe",
    "trustScoreCaution": "Use With Caution",
    "trustScoreHighRisk": "High Risk",
    "trustScoreCritical": "Critical Risk",
    "verdictApproved": "APPROVED",
    "verdictApprovedCaution": "APPROVED WITH CAUTION",
    "verdictManualReview": "MANUAL REVIEW REQUIRED",
    "verdictBlock": "BLOCK IMMEDIATELY",
    "finalVerdict": "Final Verdict",
    "riskMatrix": "Risk Matrix",
    "attackSurface": "Attack Surface Summary",
    "total": "Total",
    "reportCategory": "Category",
    "reportRecommendedFix": "Recommended Fix",
    "reportEvidenceTags": "Tags"
  },
  "zh-TW": {
    "report.title": "Repository 安全審查報告",
    "report.summary": "執行摘要",
    "report.riskLevel": "整體風險等級",
    "report.decision": "決策",
    "report.rationale": "決策理由",
    "report.scope": "掃描範圍與來源",
    "report.target": "目標",
    "report.targetType": "目標類型",
    "report.networkUsed": "取得階段使用網路",
    "report.generatedAt": "產生時間",
    "report.findings": "發現項目",
    "report.dataFlow": "資料流",
    "report.remediation": "修復建議",
    "report.codeSnippet": "程式碼片段",
    "report.explanation": "說明",
    "report.recommendedFix": "建議修復方式",
    "report.riskLevelLabel": "風險等級",
    "report.filePath": "檔案路徑",
    "report.confidence": "信心程度",
    "report.yes": "是",
    "report.no": "否",
    "trustScore": "信任評分",
    "trustScoreLabel": "可信",
    "trustScoreGenerallySafe": "大致安全",
    "trustScoreCaution": "謹慎使用",
    "trustScoreHighRisk": "高風險",
    "trustScoreCritical": "嚴重風險",
    "verdictApproved": "已核准",
    "verdictApprovedCaution": "有條件核准",
    "verdictManualReview": "需要人工審查",
    "verdictBlock": "立即封鎖",
    "finalVerdict": "最終裁定",
    "riskMatrix": "風險矩陣",
    "attackSurface": "攻擊面摘要",
    "total": "總計",
    "reportCategory": "類別",
    "reportRecommendedFix": "建議修復",
    "reportEvidenceTags": "標籤"
  },
  "zh-CN": {
    "report.title": "仓库安全审查报告",
    "report.summary": "执行摘要",
    "report.riskLevel": "整体风险等级",
    "report.decision": "决策",
    "report.rationale": "决策理由",
    "report.scope": "扫描范围与来源",
    "report.target": "目标",
    "report.targetType": "目标类型",
    "report.networkUsed": "获取阶段使用网络",
    "report.generatedAt": "生成时间",
    "report.findings": "发现项",
    "report.dataFlow": "数据流",
    "report.remediation": "修复建议",
    "report.codeSnippet": "代码片段",
    "report.explanation": "说明",
    "report.recommendedFix": "建议修复方式",
    "report.riskLevelLabel": "风险等级",
    "report.filePath": "文件路径",
    "report.confidence": "信心程度",
    "report.yes": "是",
    "report.no": "否",
    "trustScore": "信任评分",
    "trustScoreLabel": "可信",
    "trustScoreGenerallySafe": "大致安全",
    "trustScoreCaution": "谨慎使用",
    "trustScoreHighRisk": "高风险",
    "trustScoreCritical": "严重风险",
    "verdictApproved": "已核准",
    "verdictApprovedCaution": "有条件核准",
    "verdictManualReview": "需要人工审查",
    "verdictBlock": "立即封锁",
    "finalVerdict": "最终裁定",
    "riskMatrix": "风险矩阵",
    "attackSurface": "攻击面摘要",
    "total": "总计",
    "reportCategory": "类别",
    "reportRecommendedFix": "建议修复",
    "reportEvidenceTags": "标签"
  },
};

const explanationTranslations: Record<Language, Record<string, string>> = {
  en: {
    "The package defines a postinstall lifecycle script. Lifecycle scripts run during installation and can execute code before review.":
      "The package defines a postinstall lifecycle script. Lifecycle scripts run during installation and can execute code before review.",
    "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.":
      "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.",
    "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.":
      "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.",
    "The project contains outbound network communication near sensitive local sources or process execution, making this an exfiltration candidate. Review whether sensitive data can flow to this destination.":
      "The project contains outbound network communication near sensitive local sources or process execution, making this an exfiltration candidate. Review whether sensitive data can flow to this destination.",
    "The project communicates with an external endpoint. Confirm this behavior is expected.":
      "The project communicates with an external endpoint. Confirm this behavior is expected.",
    "The project references an endpoint in a test, fixture, localhost, or example context. Confirm it cannot be used by production code.":
      "The project references an endpoint in a test, fixture, localhost, or example context. Confirm it cannot be used by production code."
  },
  "zh-TW": {
    "The package defines a postinstall lifecycle script. Lifecycle scripts run during installation and can execute code before review.":
      "此套件定義了安裝生命週期腳本。這類腳本會在安裝期間執行，可能在使用者審查前就執行程式碼。",
    "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.":
      "相依套件來源使用 git、HTTP、tarball 或本機檔案，而不是固定的 registry 版本。",
    "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.":
      "此程式碼會啟動 shell 或子程序。如果使用者可控資料流入此呼叫，可能形成命令注入或遠端程式碼執行。",
    "The project contains outbound network communication near sensitive local sources or process execution, making this an exfiltration candidate. Review whether sensitive data can flow to this destination.":
      "專案在敏感本機來源或程序執行附近存在對外網路通訊，因此屬於可能資料外洩候選。請審查敏感資料是否可能流向此目的地。",
    "The project communicates with an external endpoint. Confirm this behavior is expected.":
      "專案會與外部端點通訊。請確認此行為是否符合預期。",
    "The project references an endpoint in a test, fixture, localhost, or example context. Confirm it cannot be used by production code.":
      "專案在測試、fixture、localhost 或範例情境中引用端點。請確認它不會被正式環境程式碼使用。"
  },
  "zh-CN": {
    "The package defines a postinstall lifecycle script. Lifecycle scripts run during installation and can execute code before review.":
      "此包定义了安装生命周期脚本。这类脚本会在安装期间执行，可能在用户审查前就执行代码。",
    "Dependency source uses git, HTTP, tarball, or local file resolution rather than a pinned registry version.":
      "依赖来源使用 git、HTTP、tarball 或本地文件，而不是固定的 registry 版本。",
    "The code invokes shell or process execution. If user-controlled data reaches this call, it can become command injection or RCE.":
      "此代码会启动 shell 或子进程。如果用户可控数据流入此调用，可能形成命令注入或远程代码执行。",
    "The project contains outbound network communication near sensitive local sources or process execution, making this an exfiltration candidate. Review whether sensitive data can flow to this destination.":
      "项目在敏感本地来源或进程执行附近存在对外网络通信，因此属于可能数据泄露候选。请审查敏感数据是否可能流向此目的地。",
    "The project communicates with an external endpoint. Confirm this behavior is expected.":
      "项目会与外部端点通信。请确认此行为是否符合预期。",
    "The project references an endpoint in a test, fixture, localhost, or example context. Confirm it cannot be used by production code.":
      "项目在测试、fixture、localhost 或示例情境中引用端点。请确认它不会被正式环境代码使用。"
  }
};

const recommendedFixTranslations: Record<Language, Record<string, string>> = {
  en: {
    "Remove install-time side effects or move setup behind an explicit user command.":
      "Remove install-time side effects or move setup behind an explicit user command.",
    "Replace with a pinned registry version and verify the lockfile integrity.":
      "Replace with a pinned registry version and verify the lockfile integrity.",
    "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
      "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.",
    "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
      "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.",
    "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
      "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime."
  },
  "zh-TW": {
    "Remove install-time side effects or move setup behind an explicit user command.":
      "移除安裝期間的副作用，或將設定流程改成必須由使用者明確執行的指令。",
    "Replace with a pinned registry version and verify the lockfile integrity.":
      "改用固定的 registry 版本，並驗證 lockfile 完整性。",
    "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
      "避免 shell 執行。請使用明確參數陣列的安全 API，並加入嚴格輸入驗證。",
    "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
      "記錄預期端點、最小化傳送內容，並在送出敏感資料前要求明確同意。",
    "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
      "避免將測試或範例端點放入正式環境設定，並確認執行期間無法選用這些端點。"
  },
  "zh-CN": {
    "Remove install-time side effects or move setup behind an explicit user command.":
      "移除安装期间的副作用，或将设置流程改为必须由用户明确执行的指令。",
    "Replace with a pinned registry version and verify the lockfile integrity.":
      "改用固定的 registry 版本，并验证 lockfile 完整性。",
    "Avoid shell execution. Use safe APIs with explicit argument arrays and strict input validation.":
      "避免 shell 执行。请使用明确参数数组的安全 API，并加入严格输入验证。",
    "Document expected endpoints, minimize payloads, and require explicit consent before sending sensitive data.":
      "记录预期端点、最小化发送内容，并在发送敏感数据前要求明确同意。",
    "Keep test/example endpoints out of production configuration and ensure they cannot be selected at runtime.":
      "避免将测试或示例端点放入正式环境设置，并确认运行期间无法选用这些端点。"
  }
};

const rationaleTranslations: Record<Language, Record<string, string>> = {
  en: {
    "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward.":
      "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward.",
    "No blocking deterministic evidence was found in the configured scan scope.":
      "No blocking deterministic evidence was found in the configured scan scope."
  },
  "zh-TW": {
    "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward.":
      "一個或多個發現可能暴露祕密、執行命令、建立持久化機制，或將敏感資料送出本機。",
    "No blocking deterministic evidence was found in the configured scan scope.":
      "在目前設定的掃描範圍內，未找到需要阻擋的確定性證據。"
  },
  "zh-CN": {
    "One or more findings can expose secrets, execute commands, persist, or send sensitive data outward.":
      "一个或多个发现项可能暴露秘密、执行命令、建立持久化机制，或将敏感数据送出本地。",
    "No blocking deterministic evidence was found in the configured scan scope.":
      "在当前设定的扫描范围内，未找到需要阻挡的确定性证据。"
  }
};

const riskDescriptionPrefixes: Record<Language, string> = {
  en: "",
  "zh-TW": "",
  "zh-CN": ""
};

const residualRisk: Record<Language, string> = {
  en: "Static analysis cannot prove every runtime path. Review dynamic behavior before trusting high-risk packages.",
  "zh-TW": "靜態分析無法證明所有執行路徑。在信任高風險套件前，請審查動態行為。",
  "zh-CN": "静态分析无法证明所有执行路径。在信任高风险包前，请审查动态行为。"
};

const scanLimitations: Record<Language, string[]> = {
  en: ["Static analysis only", "No target code execution", "Limited interprocedural taint analysis"],
  "zh-TW": ["僅靜態分析", "無目標程式碼執行", "有限的程序間污染分析"],
  "zh-CN": ["仅静态分析", "无目标代码执行", "有限的程序间污染分析"]
};

export function createTranslator(lang: Language) {
  const l = (key: string): string => reportStrings[lang]?.[key] ?? reportStrings.en?.[key] ?? key;
  const rationale = (value: string): string => rationaleTranslations[lang]?.[value] ?? value;
  const explanation = (value: string): string => explanationTranslations[lang]?.[value] ?? value;
  const recommendedFix = (value: string): string => recommendedFixTranslations[lang]?.[value] ?? value;
  const riskLevel = (level: RiskLevel): string => riskLevelLabels[lang]?.[level] ?? level;
  const decision = (d: Decision): string => decisionLabels[lang]?.[d] ?? d;
  const category = (c: FindingCategory): string => categoryLabels[lang]?.[c] ?? c;
  const formatRiskLevel = (level: RiskLevel): string => `${riskLevel(level)} (${level})`;
  const formatDecision = (d: Decision): string => `${decision(d)} (${d})`;

  return {
    t: l,
    rationale,
    explanation,
    recommendedFix,
    riskLevel,
    decision,
    category,
    formatRiskLevel,
    formatDecision,
    residualRisk: residualRisk[lang] ?? residualRisk.en,
    scanLimitations: scanLimitations[lang] ?? scanLimitations.en
  };
}

export type Translator = ReturnType<typeof createTranslator>;
