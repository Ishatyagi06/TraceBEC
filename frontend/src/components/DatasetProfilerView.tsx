import React, { useState } from "react";
import { profilePhishingPotDataset } from "../services/api";
import { Database, AlertCircle, BarChart3, FileText, ShieldCheck } from "lucide-react";

export const DatasetProfilerView: React.FC = () => {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleProfilePhishingPot = () => {
    setLoading(true);
    setError(null);

    profilePhishingPotDataset()
      .then((res) => {
        setProfile(res);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to profile PhishingPot dataset");
        setLoading(false);
      });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      <div className="card" style={{ borderLeft: "4px solid var(--accent)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "var(--text-main)" }}>
                Dataset Profiling & Leakage Audit Engine
              </h2>
              <span className="badge badge-info" style={{ textTransform: "uppercase", letterSpacing: "0.05em", fontSize: "0.72rem" }}>
                PhishingPot Live Corpus
              </span>
            </div>
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", marginTop: "4px" }}>
              Profiles the real PhishingPot honeypot dataset directly from disk: analyzes raw RFC 5322 MIME transport headers, SHA-256 exact duplicates, MinHash near-duplicate clusters, and forensic readiness.
            </p>
          </div>
          <button 
            onClick={handleProfilePhishingPot} 
            className="btn btn-primary" 
            disabled={loading}
            style={{ minWidth: "220px" }}
          >
            <Database size={16} /> {loading ? "Scanning PhishingPot..." : "Profile PhishingPot Dataset"}
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ borderLeft: "4px solid #B91C1C" }}>
          <div style={{ color: "#F43F5E", fontWeight: 600 }}>Profiling Error: {error}</div>
        </div>
      )}

      {profile && (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          {/* Quick Stats Grid */}
          <div className="grid-3">
            <div className="stat-box stagger-in">
              <div className="stat-val">{profile.total_samples}</div>
              <div className="stat-label">Total .EML Files Profiled</div>
            </div>
            <div className="stat-box stagger-in">
              <div 
                className="stat-val" 
                style={{ 
                  color: profile.leakage_audit?.leakage_risk_rating === "HIGH" 
                    ? "#F43F5E" 
                    : profile.leakage_audit?.leakage_risk_rating === "MODERATE" 
                    ? "#F59E0B" 
                    : "#10B981" 
                }}
              >
                {profile.leakage_audit?.leakage_risk_rating || "MODERATE"}
              </div>
              <div className="stat-label">Template Leakage Risk</div>
            </div>
            <div className="stat-box stagger-in">
              <div className="stat-val" style={{ color: "var(--cyan)" }}>
                {profile.leakage_audit?.unique_clusters || 0}
              </div>
              <div className="stat-label">Identified Template Clusters</div>
            </div>
          </div>

          {/* Leakage Audit & Missing Fields */}
          <div className="grid-2">
            <div className="card">
              <div className="card-title">
                <AlertCircle size={20} color="var(--accent)" />
                MinHash De-duplication & Leakage Analysis
              </div>
              <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "10px", fontSize: "0.9rem" }}>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Exact Duplicates (SHA-256):</span>
                  <span style={{ fontWeight: 600, color: "var(--text-main)" }}>{profile.leakage_audit?.exact_duplicates || 0}</span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Near-Duplicate Templates (Jaccard &ge; 0.65):</span>
                  <span style={{ fontWeight: 600, color: "#F59E0B" }}>{profile.leakage_audit?.near_duplicates || 0}</span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Isolated Disjoint Clusters:</span>
                  <span style={{ fontWeight: 600, color: "var(--cyan)" }}>{profile.leakage_audit?.unique_clusters || 0}</span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Dataset Corpus Name:</span>
                  <span style={{ fontWeight: 600, color: "var(--text-main)", fontSize: "0.85rem" }}>{profile.dataset_name || "PhishingPot"}</span>
                </li>
              </ul>
            </div>

            <div className="card">
              <div className="card-title">
                <BarChart3 size={20} color="var(--accent)" />
                Token Length & Lexical Distribution
              </div>
              <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "10px", fontSize: "0.9rem" }}>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Mean Body Words:</span>
                  <span style={{ fontWeight: 600, color: "var(--text-main)" }}>{profile.length_distribution?.mean_words || 0} words</span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>95th Percentile Length:</span>
                  <span style={{ fontWeight: 600, color: "var(--text-main)" }}>{profile.length_distribution?.p95_words || 0} words</span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Forensic Readiness:</span>
                  <span style={{ fontWeight: 600, color: "#10B981", display: "flex", alignItems: "center", gap: "4px" }}>
                    <ShieldCheck size={16} /> {profile.forensic_readiness || "FULL"}
                  </span>
                </li>
                <li style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Missing Transport Headers:</span>
                  <span style={{ fontWeight: 600, color: "#10B981" }}>
                    {profile.missing_field_analysis?.received_hops?.missing_pct || 0}%
                  </span>
                </li>
              </ul>
            </div>
          </div>

          {/* Sample Files Inspected from Disk */}
          {profile.sample_files && profile.sample_files.length > 0 && (
            <div className="card">
              <div className="card-title">
                <FileText size={20} color="var(--cyan)" />
                Profiled PhishingPot .EML Files ({profile.sample_files.length} Inspected)
              </div>
              <div style={{ overflowX: "auto", marginTop: "12px" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.83rem", textAlign: "left" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)" }}>
                      <th style={{ padding: "8px 12px" }}>File</th>
                      <th style={{ padding: "8px 12px" }}>Subject</th>
                      <th style={{ padding: "8px 12px" }}>Sender</th>
                      <th style={{ padding: "8px 12px" }}>Origin IP</th>
                      <th style={{ padding: "8px 12px" }}>Relay Hops</th>
                      <th style={{ padding: "8px 12px" }}>Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profile.sample_files.map((file: any, idx: number) => (
                      <tr 
                        key={idx} 
                        style={{ 
                          borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                          backgroundColor: idx % 2 === 0 ? "rgba(255, 255, 255, 0.01)" : "transparent"
                        }}
                      >
                        <td style={{ padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", color: "var(--cyan)", fontWeight: 600 }}>
                          {file.filename}
                        </td>
                        <td style={{ padding: "8px 12px", color: "var(--text-main)", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {file.subject}
                        </td>
                        <td style={{ padding: "8px 12px", color: "var(--text-muted)", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {file.sender}
                        </td>
                        <td style={{ padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", color: "var(--text-dim)" }}>
                          {file.originating_ip || "Internal"}
                        </td>
                        <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>
                          {file.hops_count} hops
                        </td>
                        <td style={{ padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", color: "var(--text-dim)" }}>
                          {(file.size_bytes / 1024).toFixed(1)} KB
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
    </div>
  );
};

