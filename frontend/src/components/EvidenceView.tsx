import React, { useState } from "react";
import type { InvestigationRecord } from "../services/api";
import { TriageBadge } from "./TriageBadge";
import {
  ShieldAlert,
  HelpCircle,
  PhoneCall,
  Trash2,
  Network,
  ChevronDown,
  ChevronUp,
  Clock,
  ArrowRight,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";

interface EvidenceViewProps {
  record: InvestigationRecord;
  onDelete?: (id: string) => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({
  record,
  onDelete,
}) => {
  const { risk_assessment, subject, sender, source_type, id, forensic_report } = record;
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const [showRelayHops, setShowRelayHops] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const getSeverityBadge = (severity: string) => {
    const s = severity.toLowerCase();
    return <span className={`severity-badge ${s}`}>{severity}</span>;
  };

  const receivedHops = record.parsed_email?.received_hops || [];
  const hasRelayHops = receivedHops.length > 0;

  const originatingIp =
    forensic_report?.detailed_report?.technical_indicators?.originating_ip ||
    record.parsed_email?.originating_ip;

  const handleCopySummary = () => {
    const text = `TraceBEC Investigation Report [ID: ${id}]
Subject: ${subject || "(No Subject)"}
Sender: ${sender}
Source: ${source_type === "eml_upload" ? "RFC 5322 .EML Transport" : "Visible Text"}
Risk Category: ${risk_assessment.risk_category} (${Math.round(risk_assessment.calibrated_score * 100)}% score)
Decision: ${forensic_report?.decision || "N/A"}
Confidence: ${forensic_report?.fraud_confidence_percentage || "N/A"}
Key Evidence:
${(forensic_report?.key_evidence || []).map((e) => `- [${e.module}] ${e.evidence_text}`).join("\n")}
Interpretation: ${risk_assessment.score_interpretation}`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "18px" }} className="fade-in">
      
      {/* 1. Primary Investigation Header & Assessment Verdict */}
      <div
        className="card"
        style={{
          borderLeft: `4px solid ${
            risk_assessment.risk_category === "HIGH"
              ? "#F43F5E"
              : risk_assessment.risk_category === "REVIEW"
              ? "#F59E0B"
              : "#10B981"
          }`,
          background: "linear-gradient(135deg, rgba(21, 30, 50, 0.95), rgba(17, 24, 39, 0.98))",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "14px", marginBottom: "16px" }}>
          <div style={{ flex: 1, minWidth: "280px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", flexWrap: "wrap" }}>
              <TriageBadge category={risk_assessment.risk_category} score={risk_assessment.calibrated_score} />
              
              <span className="tag tag-muted" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {source_type === "eml_upload" ? "RFC 5322 Transport Headers" : "Visible Text Content"}
              </span>

              <span style={{ fontSize: "0.72rem", color: "var(--text-dim)", fontFamily: "'JetBrains Mono', monospace" }}>
                Ref: {id.slice(0, 8)}...
              </span>
            </div>

            <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "var(--text-main)", marginBottom: "4px", lineHeight: 1.3 }}>
              {subject || <span style={{ color: "var(--text-dim)", fontStyle: "italic" }}>(No Subject Specified)</span>}
            </h2>

            <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", display: "flex", gap: "6px", alignItems: "baseline" }}>
              <span style={{ color: "var(--text-dim)" }}>Sender:</span>
              <span style={{ color: "var(--text-main)", fontWeight: 500, fontFamily: "'JetBrains Mono', monospace" }}>{sender}</span>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={handleCopySummary}
              className="btn btn-secondary"
              style={{ padding: "6px 12px", fontSize: "0.78rem" }}
              title="Copy investigation summary for ticket notes"
            >
              {copied ? <Check size={13} color="#2DD4BF" /> : <Copy size={13} />}
              {copied ? "Copied" : "Copy Summary"}
            </button>

            {onDelete && (
              <button
                onClick={() => onDelete(id)}
                className="btn btn-danger"
                style={{ padding: "6px 12px", fontSize: "0.78rem" }}
                title="Purge record"
              >
                <Trash2 size={13} /> Purge
              </button>
            )}
          </div>
        </div>

        {/* Confidence & Synthesis Gauge */}
        {forensic_report && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: "14px",
              padding: "16px",
              backgroundColor: "rgba(0, 0, 0, 0.3)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border-subtle)",
            }}
          >
            <div>
              <div style={{ fontSize: "0.72rem", textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--text-dim)", fontWeight: 600 }}>
                Forensic Engine Decision
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginTop: "4px" }}>
                <span
                  className="decision-glow"
                  style={{
                    fontSize: "1.35rem",
                    fontWeight: 800,
                    color:
                      forensic_report.decision === "Phishing"
                        ? "var(--risk-high-text)"
                        : forensic_report.decision === "Uncertain"
                        ? "var(--risk-review-text)"
                        : "var(--risk-low-text)",
                    borderRadius: "6px",
                    padding: "0 4px",
                  }}
                >
                  {forensic_report.decision}
                </span>
                <span style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                  (Threshold: {risk_assessment.decision_threshold})
                </span>
              </div>
            </div>

            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.72rem", textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--text-dim)", fontWeight: 600 }}>
                <span>Fraud Confidence Score</span>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--text-main)" }}>
                  {forensic_report.fraud_confidence_percentage}
                </span>
              </div>
              <div style={{ marginTop: "8px", height: "8px", backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: "999px", overflow: "hidden" }}>
                <div
                  className="bar-fill-animated"
                  style={{
                    height: "100%",
                    width: forensic_report.fraud_confidence_percentage,
                    backgroundColor:
                      forensic_report.fraud_confidence_score >= 0.70
                        ? "#F43F5E"
                        : forensic_report.fraud_confidence_score >= 0.35
                        ? "#F59E0B"
                        : "#10B981",
                    borderRadius: "999px",
                  }}
                />
              </div>
              <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginTop: "6px" }}>
                Synthesized across NLP, headers, infrastructure reputation, and campaign correlation.
              </div>
            </div>

            <div style={{ gridColumn: "1 / -1", borderTop: "1px solid rgba(255, 255, 255, 0.05)", paddingTop: "10px" }}>
              <div style={{ fontSize: "0.85rem", color: "var(--text-main)", lineHeight: 1.5 }}>
                <strong style={{ color: "var(--accent-rose-bright)" }}>Analysis Interpretation:</strong>{" "}
                {risk_assessment.score_interpretation}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Structured Evidence Analysis: Observed vs Inferred vs Unavailable */}
      <div className="grid-3">
        {/* Column 1: Observed Evidence (Verified Facts) */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-title" style={{ color: "var(--accent-rose-bright)" }}>
            <ShieldAlert size={16} />
            Observed Evidence (Facts)
            <span className="tag tag-muted" style={{ marginLeft: "auto", fontSize: "0.68rem" }}>
              {risk_assessment.observed_evidence.length} items
            </span>
          </div>
          <p style={{ fontSize: "0.78rem", color: "var(--text-dim)", marginBottom: "12px", lineHeight: 1.4 }}>
            Empirically confirmed from parsed headers, cryptographic signatures, or exact payload patterns.
          </p>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "8px" }}>
            {risk_assessment.observed_evidence.length === 0 ? (
              <div style={{ color: "var(--text-dim)", fontSize: "0.82rem", fontStyle: "italic", padding: "10px 0" }}>
                No anomalous observable indicators identified in message structure.
              </div>
            ) : (
              risk_assessment.observed_evidence.map((sig, idx) => (
                <div key={idx} className="signal-item">
                  <div className="signal-header">
                    <span className="signal-title">{sig.title}</span>
                    {getSeverityBadge(sig.severity)}
                  </div>
                  <div className="signal-desc">{sig.description}</div>
                  <div style={{ fontSize: "0.70rem", color: "var(--text-dim)", marginTop: "4px" }}>
                    Category: {sig.category}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Column 2: Inferred Findings (Model & Correlation) */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-title" style={{ color: "var(--accent-teal-bright)" }}>
            <Sparkles size={16} />
            Inferred Analytical Findings
            <span className="tag tag-muted" style={{ marginLeft: "auto", fontSize: "0.68rem" }}>
              Heuristics & ML
            </span>
          </div>
          <p style={{ fontSize: "0.78rem", color: "var(--text-dim)", marginBottom: "12px", lineHeight: 1.4 }}>
            Probabilistic assessments derived from NLP feature weights and historical threat databases.
          </p>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "10px" }}>
            {forensic_report?.key_evidence && forensic_report.key_evidence.length > 0 ? (
              forensic_report.key_evidence.map((ke, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: "10px 12px",
                    backgroundColor: "rgba(0, 0, 0, 0.22)",
                    borderRadius: "var(--radius-sm)",
                    border: "1px solid var(--border-subtle)",
                    fontSize: "0.82rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                    <span style={{ fontSize: "0.70rem", fontWeight: 700, color: "var(--accent-teal-bright)", textTransform: "uppercase" }}>
                      {ke.module}
                    </span>
                    <span
                      style={{
                        fontSize: "0.65rem",
                        padding: "1px 5px",
                        borderRadius: "3px",
                        fontWeight: 600,
                        backgroundColor:
                          ke.severity === "High"
                            ? "rgba(244, 63, 94, 0.15)"
                            : "rgba(245, 158, 11, 0.15)",
                        color: ke.severity === "High" ? "#FDA4AF" : "#FDE68A",
                      }}
                    >
                      {ke.severity}
                    </span>
                  </div>
                  <div style={{ color: "var(--text-main)", lineHeight: 1.45 }}>{ke.evidence_text}</div>
                </div>
              ))
            ) : (
              <div style={{ color: "var(--text-dim)", fontSize: "0.82rem", fontStyle: "italic", padding: "10px 0" }}>
                No high-confidence inferred threats detected.
              </div>
            )}

            {forensic_report?.module_5_campaign.potential_campaign_id && (
              <div style={{ padding: "10px 12px", backgroundColor: "rgba(99, 102, 241, 0.08)", borderRadius: "var(--radius-sm)", border: "1px solid rgba(99, 102, 241, 0.25)", fontSize: "0.80rem" }}>
                <div style={{ fontWeight: 600, color: "#C7D2FE", marginBottom: "2px" }}>
                  Correlated Cluster: {forensic_report.module_5_campaign.potential_campaign_id}
                </div>
                <div style={{ color: "var(--text-muted)" }}>
                  Similarity Match: {Math.round(forensic_report.module_5_campaign.similarity_score * 100)}%
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Column 3: Unavailable Data & Known Unknowns */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-title" style={{ color: "var(--text-muted)" }}>
            <HelpCircle size={16} />
            Unavailable Data & Limits
            <span className="tag tag-muted" style={{ marginLeft: "auto", fontSize: "0.68rem" }}>
              {risk_assessment.unavailable_evidence.length} items
            </span>
          </div>
          <p style={{ fontSize: "0.78rem", color: "var(--text-dim)", marginBottom: "12px", lineHeight: 1.4 }}>
            Explicitly documented missing evidence. Unchecked vectors are not assumed benign.
          </p>

          <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "8px", flex: 1 }}>
            {risk_assessment.unavailable_evidence.map((item, idx) => (
              <li
                key={idx}
                style={{
                  fontSize: "0.82rem",
                  color: "var(--text-muted)",
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "8px",
                  lineHeight: 1.45,
                }}
              >
                <span style={{ color: "var(--border-mid)", marginTop: "2px" }}>&bull;</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>

          <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "10px", marginTop: "12px" }}>
            <div style={{ fontSize: "0.70rem", textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-dim)", fontWeight: 600, marginBottom: "4px" }}>
              Human Verification Contract
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", lineHeight: 1.4 }}>
              Automated scoring provides decision-support triage. Critical wire executions require out-of-band human signoff.
            </div>
          </div>
        </div>
      </div>

      {/* 3. Network Relay Trajectory (RFC 5322 Headers) */}
      {hasRelayHops || originatingIp ? (
        <div className="card" style={{ backgroundColor: "rgba(15, 23, 42, 0.75)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Network size={18} color="var(--accent-teal-bright)" />
              <div>
                <span style={{ fontWeight: 600, fontSize: "0.92rem", color: "var(--text-main)" }}>
                  Network Relay Trajectory
                </span>
                <span style={{ fontSize: "0.78rem", color: "var(--text-dim)", marginLeft: "10px" }}>
                  {receivedHops.length} hops isolated from RFC 5322 Received headers
                </span>
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px" }}>
              <button
                onClick={() => setShowRelayHops(!showRelayHops)}
                className="btn btn-secondary"
                style={{ padding: "5px 10px", fontSize: "0.78rem" }}
              >
                {showRelayHops ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                {showRelayHops ? "Collapse Hops" : "Expand Relay Timeline"}
              </button>
            </div>
          </div>

          {/* Key Transit Callout */}
          <div style={{ display: "flex", alignItems: "center", gap: "16px", marginTop: "12px", padding: "10px 14px", backgroundColor: "rgba(0,0,0,0.25)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)", flexWrap: "wrap" }}>
            <div>
              <span style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase" }}>Primary Transit IP:</span>{" "}
              <code style={{ color: "var(--accent-teal-bright)", fontWeight: 600 }}>{originatingIp || "Internal Relay"}</code>
            </div>

            <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", marginLeft: "auto", fontStyle: "italic" }}>
              Parsed from authenticated MTA transport handshakes.
            </div>
          </div>

          {/* Expanded Hops Table */}
          {showRelayHops && receivedHops.length > 0 && (
            <div style={{ marginTop: "14px", overflowX: "auto" }}>
              <table className="research-table">
                <thead>
                  <tr>
                    <th>Hop</th>
                    <th>Receiving Host (By)</th>
                    <th>Sending Host (From)</th>
                    <th>Extracted IP</th>
                    <th>Transit Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {receivedHops.map((hop: any, idx: number) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--accent-teal-bright)", fontWeight: 600 }}>
                        #{hop.hop_index ?? idx + 1}
                      </td>
                      <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.78rem", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {hop.by_host || "-"}
                      </td>
                      <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.78rem", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {hop.from_host || "-"}
                      </td>
                      <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.80rem" }}>
                        {hop.ip || "Unknown"}
                      </td>
                      <td style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                        {hop.delay_seconds_from_prev !== null && hop.delay_seconds_from_prev !== undefined
                          ? `${Math.round(hop.delay_seconds_from_prev)}s`
                          : "Immediate"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        /* Secondary note when headers are not present */
        <div style={{ padding: "10px 14px", backgroundColor: "rgba(255, 255, 255, 0.02)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)", fontSize: "0.78rem", color: "var(--text-dim)", display: "flex", alignItems: "center", gap: "8px" }}>
          <Clock size={14} color="var(--text-dim)" />
          <span>
            Transport relay headers unavailable for visible text submission.
          </span>
        </div>
      )}

      {/* 4. Actionable Next Steps (Incident Response Playbook) */}
      <div className="card">
        <div className="card-title">
          <PhoneCall size={16} color="var(--accent-teal-bright)" />
          Recommended Safe Next Steps (Out-of-Band Verification)
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
          {risk_assessment.safe_next_steps.map((step, idx) => (
            <div
              key={idx}
              style={{
                backgroundColor: "rgba(0, 0, 0, 0.22)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 14px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "6px", fontWeight: 600, fontSize: "0.85rem", color: "var(--text-main)", marginBottom: "4px" }}>
                <ArrowRight size={13} color="var(--accent-teal-bright)" />
                {step.action}
              </div>
              <div style={{ fontSize: "0.72rem", color: "var(--accent-teal-bright)", fontWeight: 500, marginBottom: "6px" }}>
                Channel: {step.channel}
              </div>
              <div style={{ fontSize: "0.80rem", color: "var(--text-muted)", lineHeight: 1.45 }}>
                {step.description}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Collapsible Technical Indicators */}
      {forensic_report?.detailed_report && (
        <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "8px" }}>
          <button
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            style={{
              background: "none",
              border: "none",
              color: "var(--text-dim)",
              cursor: "pointer",
              fontSize: "0.78rem",
              fontWeight: 500,
              display: "flex",
              alignItems: "center",
              gap: "6px",
              padding: "4px 0",
              transition: "color var(--transition-fast)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-main)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-dim)")}
          >
            {showTechnicalDetails ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            {showTechnicalDetails ? "Hide Raw Diagnostic Identifiers" : "Show Raw Diagnostic Identifiers"}
          </button>

          {showTechnicalDetails && (
            <div style={{ marginTop: "10px", padding: "14px", backgroundColor: "var(--bg-inset)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)", fontSize: "0.78rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "8px", fontFamily: "'JetBrains Mono', monospace" }}>
                <div>Sender IP: <code style={{ color: "var(--accent-teal-bright)" }}>{originatingIp || "N/A"}</code></div>
                <div>Extracted URLs: <code>{forensic_report.detailed_report.technical_indicators?.extracted_urls_count ?? 0}</code></div>
                <div>Relay Hops: <code>{forensic_report.detailed_report.technical_indicators?.hop_count ?? 0}</code></div>
                <div>Model Version: <code>{risk_assessment.model_version}</code></div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
