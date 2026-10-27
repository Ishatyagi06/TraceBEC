import React, { useState, useEffect } from "react";
import {
  Upload,
  FileText,
  Search,
  Trash2,
  Network,
  Database,
  Sliders,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ArrowRight,
  Shield,
  Layers,
} from "lucide-react";
import {
  analyzeEmlFile,
  analyzeVisibleText,
  getInvestigations,
  deleteInvestigation,
} from "./services/api";
import type { InvestigationRecord } from "./services/api";
import { TraceBecLogo } from "./components/TraceBecLogo";
import { EvidenceView } from "./components/EvidenceView";
import { DatasetProfilerView } from "./components/DatasetProfilerView";
import { SettingsView } from "./components/SettingsView";
import { TriageBadge } from "./components/TriageBadge";
import { CampaignGraphExplorer } from "./components/CampaignGraphExplorer";

export function App() {
  // Primary focus is the main email investigation & triage dashboard
  const [activeTab, setActiveTab] = useState<"investigation" | "campaigns" | "profiler" | "settings">("investigation");
  const [backendOnline, setBackendOnline] = useState<boolean>(true);

  // Investigation input state
  const [analysisMode, setAnalysisMode] = useState<"eml" | "text">("eml");
  const [fileToUpload, setFileToUpload] = useState<File | null>(null);
  const [textSubject, setTextSubject] = useState<string>("");
  const [textBody, setTextBody] = useState<string>("");
  const [textSender, setTextSender] = useState<string>("");
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [currentResult, setCurrentResult] = useState<InvestigationRecord | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [recentInvestigations, setRecentInvestigations] = useState<InvestigationRecord[]>([]);

  useEffect(() => {
    fetch("http://localhost:8000/health")
      .then((res) => {
        if (res.ok) setBackendOnline(true);
        else setBackendOnline(false);
      })
      .catch(() => setBackendOnline(false));

    loadInvestigations();
  }, []);

  const loadInvestigations = () => {
    getInvestigations().then((res) => {
      setRecentInvestigations(res.reverse());
    });
  };

  const handleAnalyzeEml = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileToUpload) return;
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const res = await analyzeEmlFile(fileToUpload);
      setCurrentResult(res);
      loadInvestigations();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to analyze .eml file");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalyzeText = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!textBody.trim()) return;
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const res = await analyzeVisibleText(textSubject, textBody, textSender);
      setCurrentResult(res);
      loadInvestigations();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to analyze message content");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleQuickLoad = (preset: "wire" | "payroll" | "benign") => {
    setAnalysisMode("text");
    if (preset === "wire") {
      setTextSubject("CONFIDENTIAL: Urgent Strategic Acquisition Escrow Wire Authorization");
      setTextSender("Kenneth Lay, CEO <ceo.office.corp@gmail.com>");
      setTextBody(
        "Treasury Team,\n\nI am currently in an executive session with outside counsel finalizing an urgent, confidential buyout transaction.\n\nI need you to process an initial deposit wire of $48,500.00 to the escrow account coordinates immediately before Federal Reserve wire cutoff today. Because of strict SEC non-disclosure regulations, please do not discuss this transaction on the floor until the 8-K is filed tomorrow.\n\nConfirm once you are at your terminal and ready to receive the wire coordinates."
      );
    } else if (preset === "payroll") {
      setTextSubject("Urgent: Direct Deposit Account Update for Upcoming Cycle");
      setTextSender("Sarah Davis <sarah.davis892@outlook.com>");
      setTextBody(
        "Good morning Payroll,\n\nI recently switched banking institutions due to an ongoing compromise on my prior checking account. Could you please update my direct deposit bank coordinates for the upcoming bi-weekly payroll deposit?\n\nRouting: 021000089\nAccount: 9812-4091-2210\n\nPlease confirm when this change is active."
      );
    } else {
      setTextSubject("Q3 Natural Gas Logistics Forecast & Scheduling Meeting");
      setTextSender("Eileen Peebles <eileen.peebles@enron.com>");
      setTextBody(
        "Phillip,\n\nPlease review the attached physical transmission schedules for the Southern California border pipeline. The western desk needs our desk confirmations by 2:00 PM CST today prior to market close.\n\nLet's convene in Conference Room 32B at 11:30 AM to finalize the capacity allocations."
      );
    }
  };

  const handleDeleteRecord = async (id: string) => {
    await deleteInvestigation(id);
    if (currentResult?.id === id) {
      setCurrentResult(null);
    }
    loadInvestigations();
  };

  return (
    <div className="app-container">
      {/* TraceBEC Enterprise Navbar */}
      <header className="navbar">
        <div className="brand-wrapper" onClick={() => setActiveTab("investigation")}>
          <TraceBecLogo size="md" showTagline={true} />
        </div>

        <nav className="nav-links">
          <button
            className={`nav-button ${activeTab === "investigation" ? "active" : ""}`}
            onClick={() => setActiveTab("investigation")}
          >
            <Search size={15} /> Email Investigation
          </button>
          <button
            className={`nav-button ${activeTab === "campaigns" ? "active" : ""}`}
            onClick={() => setActiveTab("campaigns")}
          >
            <Network size={15} /> Campaign Correlation
          </button>
          <button
            className={`nav-button ${activeTab === "profiler" ? "active" : ""}`}
            onClick={() => setActiveTab("profiler")}
          >
            <Database size={15} /> Dataset Profiler
          </button>
          <button
            className={`nav-button ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => setActiveTab("settings")}
          >
            <Sliders size={15} /> Settings
          </button>
        </nav>

        {/* Backend Engine Status Indicator */}
        <div 
          style={{ display: "flex", alignItems: "center", cursor: "help" }}
          title={backendOnline ? "Engine Online (Port 8000)" : "Engine Offline"}
        >
          <span
            className={backendOnline ? "status-dot-online" : "status-dot-offline"}
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              flexShrink: 0,
              backgroundColor: backendOnline ? "#10B981" : "#F43F5E",
            }}
          />
        </div>
      </header>

      {/* Main Content Workspace */}
      <main className="main-content">
        {/* TAB 1: Main Email Investigation (Primary Focus) */}
        {activeTab === "investigation" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "22px" }}>
            
            {/* Header with clear product focus */}
            <div className="section-header">
              <div>
                <h1 className="section-title">Email Forensics & BEC Threat Triage</h1>
              </div>

              {/* Quick load presets */}
              <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                <span style={{ fontSize: "0.78rem", color: "var(--text-dim)", marginRight: "4px" }}>Sample Incidents:</span>
                <button onClick={() => handleQuickLoad("wire")} className="btn btn-secondary" style={{ padding: "4px 9px", fontSize: "0.76rem" }}>
                  CEO Wire Fraud
                </button>
                <button onClick={() => handleQuickLoad("payroll")} className="btn btn-secondary" style={{ padding: "4px 9px", fontSize: "0.76rem" }}>
                  Payroll Reroute
                </button>
                <button onClick={() => handleQuickLoad("benign")} className="btn btn-secondary" style={{ padding: "4px 9px", fontSize: "0.76rem" }}>
                  Benign Logistics
                </button>
              </div>
            </div>

            {/* Input Submission Card */}
            <div className={`card forensic-scan-wrapper`}>
              {/* Forensic scan line — visible only while analyzing */}
              {analyzing && <div className="forensic-scan-line" />}
              {analyzing && (
                <div style={{ marginBottom: "12px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                    {["Header Parse", "Auth Check", "NLP Engine", "Threat Intel", "Scoring"].map((stage, i) => (
                      <div key={stage} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <div className="forensic-stage-dot active" style={{ animationDelay: `${i * 0.18}s` }} />
                        <span style={{ fontSize: "0.68rem", color: "var(--text-dim)", whiteSpace: "nowrap" }}>{stage}</span>
                        {i < 4 && <span style={{ color: "var(--border-mid)", fontSize: "0.7rem", margin: "0 2px" }}>›</span>}
                      </div>
                    ))}
                  </div>
                  <div className="forensic-progress-bar">
                    <div className="forensic-progress-fill" style={{ width: "100%" }} />
                  </div>
                </div>
              )}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "14px", marginBottom: "18px" }}>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    className={`btn ${analysisMode === "eml" ? "btn-primary" : "btn-secondary"}`}
                    onClick={() => setAnalysisMode("eml")}
                  >
                    <Upload size={14} /> Upload (.EML)
                  </button>
                  <button
                    className={`btn ${analysisMode === "text" ? "btn-primary" : "btn-secondary"}`}
                    onClick={() => setAnalysisMode("text")}
                  >
                    <FileText size={14} /> Visible Message Text
                  </button>
                </div>

                <div style={{ fontSize: "0.76rem", color: "var(--text-dim)", display: "flex", alignItems: "center", gap: "5px" }}>
                  <Shield size={13} color="var(--accent-teal-bright)" />
                  <span>5 Parallel Forensic Engines active</span>
                </div>
              </div>

              {/* Form A: EML Upload */}
              {analysisMode === "eml" ? (
                <form onSubmit={handleAnalyzeEml} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                  <div
                    className="drop-zone"
                    onClick={() => document.getElementById("eml-input")?.click()}
                  >
                    <Upload size={28} color="var(--accent-teal-bright)" style={{ margin: "0 auto 10px" }} />
                    <div style={{ fontWeight: 600, color: "var(--text-main)", marginBottom: "4px", fontSize: "0.92rem" }}>
                      {fileToUpload ? fileToUpload.name : "Select or Drop (.EML) File"}
                    </div>
                    <div style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                      Full transport headers parsed: Received hops, DKIM/SPF/DMARC, Origin IP, and MIME structure
                    </div>
                    <input
                      id="eml-input"
                      type="file"
                      accept=".eml,.txt"
                      style={{ display: "none" }}
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setFileToUpload(e.target.files[0]);
                        }
                      }}
                    />
                  </div>

                  <div style={{ display: "flex", justifyContent: "flex-end" }}>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={!fileToUpload || analyzing}
                      style={{ minWidth: "160px" }}
                    >
                      {analyzing ? (
                        <>
                          <Loader2 size={14} className="spin" style={{ animation: "spin 1s linear infinite" }} />
                          Analyzing Hops...
                        </>
                      ) : (
                        <>
                          Run Forensic Analysis <ArrowRight size={14} />
                        </>
                      )}
                    </button>
                  </div>
                </form>
              ) : (
                /* Form B: Visible Text Submission */
                <form onSubmit={handleAnalyzeText} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                  <div className="grid-2">
                    <div className="form-group">
                      <label className="form-label">Visible Sender (Display Name & Header Address)</label>
                      <input
                        className="form-input"
                        placeholder="e.g. Kenneth Lay, CEO <ceo.office.corp@gmail.com>"
                        value={textSender}
                        onChange={(e) => setTextSender(e.target.value)}
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Email Subject</label>
                      <input
                        className="form-input"
                        placeholder="e.g. URGENT: Acquisition Escrow Wire Authorization"
                        value={textSubject}
                        onChange={(e) => setTextSubject(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Email Body Content</label>
                    <textarea
                      className="form-textarea"
                      placeholder="Paste the email message body here..."
                      value={textBody}
                      onChange={(e) => setTextBody(e.target.value)}
                    />
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                    <span style={{ fontSize: "0.76rem", color: "var(--text-dim)", lineHeight: 1.4 }}>
                      Network routing and transport headers are unavailable in plain-text mode &mdash; clearly recorded in evidence findings.
                    </span>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={!textBody.trim() || analyzing}
                      style={{ minWidth: "160px" }}
                    >
                      {analyzing ? (
                        <>
                          <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />
                          Analyzing Text...
                        </>
                      ) : (
                        <>
                          Analyze Message <ArrowRight size={14} />
                        </>
                      )}
                    </button>
                  </div>
                </form>
              )}

              {/* Error Message */}
              {errorMessage && (
                <div className="notice notice-error" style={{ marginTop: "14px" }}>
                  <AlertCircle size={16} />
                  <span>{errorMessage}</span>
                </div>
              )}
            </div>

            {/* Active Investigation Result View */}
            {currentResult ? (
              <div className="result-reveal">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <CheckCircle2 size={16} color="var(--accent-teal-bright)" />
                    <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-main)" }}>
                      Active Investigation Report
                    </span>
                  </div>
                  <button
                    onClick={() => setCurrentResult(null)}
                    className="btn btn-secondary"
                    style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                  >
                    Close View
                  </button>
                </div>

                <EvidenceView
                  record={currentResult}
                  onDelete={handleDeleteRecord}
                />
              </div>
            ) : (
              /* Empty State when no result is currently open */
              recentInvestigations.length === 0 && (
                <div
                  className="card"
                  style={{
                    textAlign: "center",
                    padding: "48px 24px",
                    backgroundColor: "rgba(17, 24, 39, 0.4)",
                    border: "1px dashed var(--border-subtle)",
                  }}
                >
                  <Layers size={36} color="var(--border-mid)" style={{ margin: "0 auto 12px" }} />
                  <div style={{ fontSize: "1.05rem", fontWeight: 600, color: "var(--text-main)", marginBottom: "6px" }}>
                    No Active Investigation
                  </div>
                  <p style={{ fontSize: "0.835rem", color: "var(--text-muted)", maxWidth: "480px", margin: "0 auto 16px" }}>
                    Upload an RFC 5322 .eml file or paste visible email text above to execute the 5-module forensic pipeline and generate a calibrated BEC threat report.
                  </p>
                </div>
              )
            )}

            {/* Recent Investigations History */}
            {recentInvestigations.length > 0 && !currentResult && (
              <div className="card">
                <div className="card-title">
                  <Search size={16} color="var(--accent-teal-bright)" />
                  Prior Investigation Sessions
                  <span className="tag tag-muted" style={{ marginLeft: "auto", fontSize: "0.70rem" }}>
                    {recentInvestigations.length} records recorded
                  </span>
                </div>

                <div style={{ overflowX: "auto" }}>
                  <table className="research-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Subject</th>
                        <th>Sender</th>
                        <th>Source</th>
                        <th>Assessment</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentInvestigations.map((inv) => (
                        <tr key={inv.id}>
                          <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.76rem", color: "var(--text-dim)", whiteSpace: "nowrap" }}>
                            {inv.timestamp_iso.slice(0, 19).replace("T", " ")}
                          </td>
                          <td style={{ fontWeight: 500, maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {inv.subject || <span style={{ color: "var(--text-dim)", fontStyle: "italic" }}>(No Subject)</span>}
                          </td>
                          <td style={{ color: "var(--text-muted)", fontSize: "0.80rem", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {inv.sender}
                          </td>
                          <td>
                            <span className="tag tag-muted" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                              {inv.source_type === "eml_upload" ? ".eml" : "text"}
                            </span>
                          </td>
                          <td>
                            <TriageBadge category={inv.risk_assessment.risk_category} score={inv.risk_assessment.calibrated_score} />
                          </td>
                          <td>
                            <div style={{ display: "flex", gap: "6px" }}>
                              <button
                                onClick={() => setCurrentResult(inv)}
                                className="btn btn-secondary"
                                style={{ padding: "4px 10px", fontSize: "0.76rem" }}
                              >
                                View Report
                              </button>
                              <button
                                onClick={() => handleDeleteRecord(inv.id)}
                                className="btn btn-danger"
                                style={{ padding: "4px 8px", fontSize: "0.76rem" }}
                                title="Purge record"
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Campaign Graph Explorer */}
        {activeTab === "campaigns" && <CampaignGraphExplorer />}

        {/* TAB 3: Dataset Profiler */}
        {activeTab === "profiler" && <DatasetProfilerView />}

        {/* TAB 4: Privacy & Settings */}
        {activeTab === "settings" && <SettingsView />}
      </main>
    </div>
  );
}

export default App;
