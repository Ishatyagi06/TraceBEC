import React, { useState, useEffect } from "react";
import { getInvestigations, deleteInvestigation } from "../services/api";
import { Sliders, Trash2, Lock } from "lucide-react";

export const SettingsView: React.FC = () => {
  const [retentionMode, setRetentionMode] = useState<string>("investigation");
  const [investigationCount, setInvestigationCount] = useState<number>(0);
  const [purging, setPurging] = useState<boolean>(false);
  const [purgeMessage, setPurgeMessage] = useState<string | null>(null);

  useEffect(() => {
    getInvestigations().then((res) => {
      setInvestigationCount(res.length);
    });
  }, []);

  const handlePurgeAll = async () => {
    setPurging(true);
    setPurgeMessage(null);
    try {
      const records = await getInvestigations();
      for (const r of records) {
        await deleteInvestigation(r.id);
      }
      setInvestigationCount(0);
      setPurgeMessage("All investigation records permanently purged from local storage.");
    } catch (e: any) {
      setPurgeMessage(`Purge error: ${e.message}`);
    } finally {
      setPurging(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div className="card" style={{ borderLeft: "4px solid var(--accent)" }}>
        <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "var(--text-main)" }}>
          Privacy, Retention & Security Configuration
        </h2>
        <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", marginTop: "4px" }}>
          Configure data retention policies, execute user-triggered data purges, and review untrusted input safeguards.
        </p>
      </div>

      <div className="grid-2">
        {/* Retention Policy Card */}
        <div className="card">
          <div className="card-title">
            <Sliders size={20} color="var(--accent)" />
            Data Retention Mode
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <label style={{ display: "flex", alignItems: "flex-start", gap: "12px", cursor: "pointer" }}>
              <input
                type="radio"
                name="retention"
                value="investigation"
                checked={retentionMode === "investigation"}
                onChange={(e) => setRetentionMode(e.target.value)}
                style={{ marginTop: "4px" }}
              />
              <div>
                <strong style={{ color: "var(--text-main)", fontSize: "0.95rem" }}>
                  Investigation Mode (Default)
                </strong>
                <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "2px" }}>
                  Stores parsed evidence and triage assessments in local encrypted storage for SOC audit reviews. Records can be individually or bulk deleted.
                </p>
              </div>
            </label>

            <label style={{ display: "flex", alignItems: "flex-start", gap: "12px", cursor: "pointer" }}>
              <input
                type="radio"
                name="retention"
                value="ephemeral"
                checked={retentionMode === "ephemeral"}
                onChange={(e) => setRetentionMode(e.target.value)}
                style={{ marginTop: "4px" }}
              />
              <div>
                <strong style={{ color: "var(--text-main)", fontSize: "0.95rem" }}>
                  Ephemeral Analysis Mode (Zero Local Persistence)
                </strong>
                <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "2px" }}>
                  Performs inference in-memory. Raw message bodies, headers, and assessments are immediately dropped from memory after the response is returned.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Data Purge & Audit Controls */}
        <div className="card">
          <div className="card-title">
            <Trash2 size={20} color="#B91C1C" />
            Storage Purge Controls
          </div>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "16px" }}>
            Active local audit records currently stored: <strong style={{ color: "var(--text-main)" }}>{investigationCount}</strong>
          </p>

          <button
            onClick={handlePurgeAll}
            disabled={purging || investigationCount === 0}
            className="btn btn-danger"
            style={{ width: "100%", justifyContent: "center" }}
          >
            <Trash2 size={16} /> Purge All Local Audit Records
          </button>

          {purgeMessage && (
            <div style={{ marginTop: "12px", padding: "10px", backgroundColor: "rgba(13, 148, 136, 0.08)", border: "1px solid #0D9488", borderRadius: "4px", fontSize: "0.85rem", color: "#0D9488" }}>
              {purgeMessage}
            </div>
          )}
        </div>
      </div>

      {/* Untrusted Email Security Contract */}
      <div className="card">
        <div className="card-title">
          <Lock size={20} color="var(--accent)" />
          Untrusted Content & Input Sanitization Contract
        </div>
        <ul style={{ listStyle: "none", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
          <li style={{ backgroundColor: "var(--bg-inset)", padding: "14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
            <div style={{ fontWeight: 600, fontSize: "0.9rem", color: "var(--text-main)", marginBottom: "4px" }}>
              Script & DOM Neutralization
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              HTML email bodies are stripped of script tags, iframes, embeds, and malicious CSS before inspection.
            </div>
          </li>
          <li style={{ backgroundColor: "var(--bg-inset)", padding: "14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
            <div style={{ fontWeight: 600, fontSize: "0.9rem", color: "var(--text-main)", marginBottom: "4px" }}>
              Zero Attachment Execution
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Attachments are parsed strictly for structural MIME metadata (extension, size, header disposition). Files are never executed or unzipped.
            </div>
          </li>
          <li style={{ backgroundColor: "var(--bg-inset)", padding: "14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
            <div style={{ fontWeight: 600, fontSize: "0.9rem", color: "var(--text-main)", marginBottom: "4px" }}>
              Prompt Injection Defense
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              All email text is treated strictly as passive data, preventing instruction hijack or adversarial override in language models.
            </div>
          </li>
        </ul>
      </div>
    </div>
  );
};
