import React, { useState, useEffect } from "react";
import { getCampaignGraph } from "../services/api";
import {
  Search,
  Copy,
  Check,
  ZoomIn,
  ZoomOut,
  RefreshCw,
  ChevronDown,
} from "lucide-react";

interface NodeItem {
  id: string;
  label: string;
  type: string;
  color: string;
  size: number;
  x: number;
  y: number;
  members?: number;
  connections?: number;
  sender?: string;
  origin_ip?: string;
  domain?: string;
  description?: string;
}

interface EdgeItem {
  id: string;
  source: string;
  target: string;
  type: string;
  color: string;
}

export const CampaignGraphExplorer: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>("camp_d5440b4df3ff");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [campaignsList, setCampaignsList] = useState<any[]>([]);
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [edges, setEdges] = useState<EdgeItem[]>([]);
  const [selectedCampaignMeta, setSelectedCampaignMeta] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Node type visibility checkboxes
  const [visibleTypes, setVisibleTypes] = useState<Record<string, boolean>>({
    email: true,
    campaign_candidate: true,
    url: true,
    domain: true,
    ip: true,
    sender_identity: true,
    html_fingerprint: true,
    attachment_hash: true,
  });

  const nodeTypeMetadata = [
    { key: "email", label: "Email", count: "306", color: "#3B82F6" },
    { key: "campaign_candidate", label: "Campaign candidate", count: "22", color: "#F87171" },
    { key: "url", label: "URL", count: "1,405", color: "#FB923C" },
    { key: "domain", label: "Domain", count: "246", color: "#34D399" },
    { key: "ip", label: "IP", count: "1,021", color: "#F59E0B" },
    { key: "sender_identity", label: "Sender identity", count: "248", color: "#818CF8" },
    { key: "html_fingerprint", label: "HTML fingerprint", count: "255", color: "#C084FC" },
    { key: "attachment_hash", label: "Attachment hash", count: "24", color: "#A3E635" },
  ];

  const fetchGraph = async (cId: string, search?: string) => {
    try {
      setLoading(true);
      const data = await getCampaignGraph(cId, search);
      setNodes(data.nodes || []);
      setEdges(data.edges || []);
      setCampaignsList(data.campaigns_list || []);
      setSelectedCampaignMeta(data.selected_campaign || null);
      if (data.nodes && data.nodes.length > 0) {
        setSelectedNode(data.nodes[0]);
      }
    } catch (err) {
      console.error("Failed to load campaign graph:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph(selectedCampaignId, searchQuery);
  }, [selectedCampaignId]);

  const handleCopyId = () => {
    if (selectedCampaignMeta?.id) {
      navigator.clipboard.writeText(selectedCampaignMeta.id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleToggleAll = (val: boolean) => {
    const next: Record<string, boolean> = {};
    Object.keys(visibleTypes).forEach((k) => (next[k] = val));
    setVisibleTypes(next);
  };

  const filteredCampaigns = campaignsList.filter(
    (c) =>
      c.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.sample_subject && c.sample_subject.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const filteredNodes = nodes.filter((n) => visibleTypes[n.type] !== false);

  // Mouse drag handlers for canvas panning
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === "svg" || (e.target as HTMLElement).tagName === "rect") {
      setIsDraggingCanvas(true);
      setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDraggingCanvas) {
      setPanOffset({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDraggingCanvas(false);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)", backgroundColor: "#0C0F17", borderRadius: "12px", border: "1px solid rgba(255,255,255,0.08)", overflow: "hidden", color: "#E2E8F0" }}>
      
      {/* Top Header Bar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 20px", borderBottom: "1px solid rgba(255,255,255,0.08)", backgroundColor: "#0F1420" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--accent-rose-bright)", fontWeight: 700, fontSize: "0.95rem" }}>
            <span>Campaign Graph Explorer</span>
            <ChevronDown size={14} />
          </div>
          <span style={{ fontSize: "0.78rem", color: "#64748B" }}>
            40 of 3,527 nodes shown (Phishing Pot Benchmark)
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span className="tag" style={{ fontSize: "0.72rem", backgroundColor: "var(--accent-rose-subtle)", color: "var(--accent-rose-bright)", border: "1px solid var(--accent-rose-border)" }}>
            Dataset: rf-peixoto/phishing_pot (306 .eml subset)
          </span>
          <button
            onClick={() => { setZoomLevel(1); setPanOffset({ x: 0, y: 0 }); }}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "6px", padding: "6px", color: "#94A3B8", cursor: "pointer" }}
            title="Reset View"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={() => setZoomLevel((z) => Math.min(2.5, z + 0.2))}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "6px", padding: "6px", color: "#94A3B8", cursor: "pointer" }}
            title="Zoom In"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={() => setZoomLevel((z) => Math.max(0.4, z - 0.2))}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "6px", padding: "6px", color: "#94A3B8", cursor: "pointer" }}
            title="Zoom Out"
          >
            <ZoomOut size={14} />
          </button>
        </div>
      </div>

      {/* Main Workspace Body */}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        
        {/* Left Sidebar */}
        <div style={{ width: "280px", minWidth: "280px", borderRight: "1px solid rgba(255,255,255,0.08)", backgroundColor: "#090D15", display: "flex", flexDirection: "column", overflowY: "auto" }}>
          
          {/* SEARCH */}
          <div style={{ padding: "14px 16px 8px 16px" }}>
            <div style={{ fontSize: "0.68rem", fontWeight: 700, color: "#64748B", letterSpacing: "0.08em", marginBottom: "6px" }}>
              SEARCH
            </div>
            <div style={{ position: "relative" }}>
              <Search size={14} color="#64748B" style={{ position: "absolute", left: "10px", top: "10px" }} />
              <input
                type="text"
                placeholder="Search by label or ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: "100%",
                  backgroundColor: "#131926",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: "6px",
                  padding: "7px 10px 7px 32px",
                  color: "#F1F5F9",
                  fontSize: "0.78rem",
                  outline: "none",
                }}
              />
            </div>
          </div>

          {/* CAMPAIGNS LIST */}
          <div style={{ padding: "8px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <span style={{ fontSize: "0.68rem", fontWeight: 700, color: "#64748B", letterSpacing: "0.08em" }}>
                CAMPAIGNS
              </span>
              <button
                onClick={() => setSearchQuery("")}
                style={{ background: "none", border: "none", color: "#38BDF8", fontSize: "0.72rem", cursor: "pointer", padding: 0 }}
              >
                Show all
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "170px", overflowY: "auto" }}>
              {filteredCampaigns.map((camp) => {
                const isSelected = selectedCampaignId === camp.id;
                return (
                  <div
                    key={camp.id}
                    onClick={() => setSelectedCampaignId(camp.id)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "6px 8px",
                      borderRadius: "6px",
                      backgroundColor: isSelected ? "rgba(244, 63, 94, 0.15)" : "transparent",
                      border: isSelected ? "1px solid rgba(244, 63, 94, 0.5)" : "1px solid transparent",
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", minWidth: 0 }}>
                      <span style={{ width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "#F87171", flexShrink: 0 }} />
                      <span style={{ fontSize: "0.78rem", color: isSelected ? "#FFF" : "#94A3B8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {camp.label}
                      </span>
                    </div>
                    <span
                      style={{
                        padding: "1px 6px",
                        borderRadius: "10px",
                        fontSize: "0.65rem",
                        backgroundColor: "rgba(239, 68, 68, 0.2)",
                        color: "#FCA5A5",
                        fontWeight: 600,
                        flexShrink: 0,
                      }}
                    >
                      {camp.member_count} mails
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* NODE TYPES */}
          <div style={{ padding: "12px 16px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <span style={{ fontSize: "0.68rem", fontWeight: 700, color: "#64748B", letterSpacing: "0.08em" }}>
                NODE TYPES
              </span>
              <div style={{ display: "flex", gap: "6px" }}>
                <button
                  onClick={() => handleToggleAll(true)}
                  style={{ background: "none", border: "none", color: "#38BDF8", fontSize: "0.70rem", cursor: "pointer", padding: 0 }}
                >
                  All
                </button>
                <span style={{ color: "#475569", fontSize: "0.70rem" }}>/</span>
                <button
                  onClick={() => handleToggleAll(false)}
                  style={{ background: "none", border: "none", color: "#94A3B8", fontSize: "0.70rem", cursor: "pointer", padding: 0 }}
                >
                  None
                </button>
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {nodeTypeMetadata.map((t) => (
                <label
                  key={t.key}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    fontSize: "0.76rem",
                    color: visibleTypes[t.key] ? "#CBD5E1" : "#475569",
                    cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <input
                      type="checkbox"
                      checked={visibleTypes[t.key] || false}
                      onChange={(e) => setVisibleTypes({ ...visibleTypes, [t.key]: e.target.checked })}
                      style={{ accentColor: t.color, cursor: "pointer" }}
                    />
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: t.color }} />
                    <span>{t.label}</span>
                  </div>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.72rem", color: "#64748B" }}>
                    {t.count}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Selected Campaign Card (Matching Bottom Left of Screenshot) */}
          {selectedCampaignMeta && (
            <div
              style={{
                marginTop: "auto",
                margin: "12px 14px",
                padding: "14px",
                backgroundColor: "#111726",
                borderRadius: "8px",
                border: "1px solid var(--accent-rose-border)",
                boxShadow: "0 4px 16px rgba(0,0,0,0.5), 0 0 14px rgba(190, 24, 93, 0.15)",
              }}
            >
              <div style={{ display: "inline-block", padding: "2px 8px", borderRadius: "12px", backgroundColor: "var(--accent-rose)", color: "#FFF", fontSize: "0.68rem", fontWeight: 700, marginBottom: "8px", boxShadow: "0 0 8px rgba(190, 24, 93, 0.4)" }}>
                Campaign candidate
              </div>
              <div style={{ fontWeight: 700, fontSize: "0.88rem", color: "#F8FAFC", marginBottom: "2px" }}>
                {selectedCampaignMeta.label}
              </div>
              <div style={{ fontSize: "0.72rem", color: "#64748B", fontFamily: "'JetBrains Mono', monospace", marginBottom: "12px" }}>
                {selectedCampaignMeta.id}
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "0.76rem", marginBottom: "12px" }}>
                <div>
                  <div style={{ color: "#64748B", fontSize: "0.70rem" }}>Members</div>
                  <div style={{ fontWeight: 700, color: "#F1F5F9", fontSize: "0.85rem" }}>
                    {selectedCampaignMeta.member_count}
                  </div>
                </div>
                <div>
                  <div style={{ color: "#64748B", fontSize: "0.70rem" }}>Connections</div>
                  <div style={{ fontWeight: 700, color: "#F1F5F9", fontSize: "0.85rem" }}>
                    {selectedCampaignMeta.connections_count}
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  onClick={() => { setZoomLevel(1); setPanOffset({ x: 0, y: 0 }); }}
                  style={{
                    flex: 1,
                    backgroundColor: "rgba(255,255,255,0.06)",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: "4px",
                    color: "#E2E8F0",
                    fontSize: "0.72rem",
                    padding: "6px",
                    cursor: "pointer",
                    fontWeight: 600,
                  }}
                >
                  Show full graph
                </button>
                <button
                  onClick={handleCopyId}
                  style={{
                    backgroundColor: "rgba(255,255,255,0.06)",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: "4px",
                    color: copied ? "#10B981" : "#94A3B8",
                    fontSize: "0.72rem",
                    padding: "6px 10px",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "4px",
                  }}
                  title="Copy Campaign ID"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copied ? "Copied" : "Copy ID"}</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Center / Right Graph Canvas */}
        <div
          style={{ flex: 1, position: "relative", backgroundColor: "#060910", overflow: "hidden", cursor: isDraggingCanvas ? "grabbing" : "grab" }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          {loading && (
            <div style={{ position: "absolute", top: "20px", right: "20px", padding: "6px 12px", backgroundColor: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "6px", fontSize: "0.75rem", color: "#38BDF8", zIndex: 10 }}>
              Rendering Phishing Pot Knowledge Graph...
            </div>
          )}

          {/* Interactive SVG Graph Canvas */}
          <svg
            width="100%"
            height="100%"
            style={{ width: "100%", height: "100%", display: "block" }}
          >
            <rect width="100%" height="100%" fill="#070A12" />

            <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
              
              {/* Edges with smooth clean lines */}
              {edges.map((edge) => {
                const sourceNode = nodes.find((n) => n.id === edge.source);
                const targetNode = nodes.find((n) => n.id === edge.target);
                if (!sourceNode || !targetNode) return null;
                return (
                  <g key={edge.id}>
                    <line
                      x1={sourceNode.x}
                      y1={sourceNode.y}
                      x2={targetNode.x}
                      y2={targetNode.y}
                      stroke={edge.color || "rgba(59, 130, 246, 0.6)"}
                      strokeWidth={1.75}
                      strokeOpacity={0.7}
                    />
                  </g>
                );
              })}

              {/* Clean Nodes with readable background pills */}
              {filteredNodes.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                const isCampaign = node.type === "campaign_candidate";
                const labelText = node.label.length > 38 ? `${node.label.slice(0, 36)}...` : node.label;
                const textWidth = Math.min(240, labelText.length * 6.5 + 14);

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={(e) => { e.stopPropagation(); setSelectedNode(node); }}
                    style={{ cursor: "pointer" }}
                  >
                    {/* Glowing halo for selected or campaign node */}
                    {(isCampaign || isSelected) && (
                      <circle
                        r={node.size + 6}
                        fill={isCampaign ? "rgba(244, 63, 94, 0.2)" : "rgba(56, 189, 248, 0.2)"}
                        stroke={isCampaign ? "rgba(244, 63, 94, 0.5)" : "rgba(56, 189, 248, 0.5)"}
                        strokeWidth={1.5}
                      />
                    )}

                    {/* Node Circle */}
                    <circle
                      r={node.size}
                      fill={node.color}
                      stroke={isSelected ? "#FFF" : "rgba(255,255,255,0.4)"}
                      strokeWidth={isSelected ? 2.5 : 1}
                      filter="drop-shadow(0 2px 4px rgba(0,0,0,0.5))"
                    />

                    {/* Clean Label Pill Background */}
                    <rect
                      x={node.size + 6}
                      y={-10}
                      width={textWidth}
                      height={20}
                      rx={4}
                      fill="rgba(15, 23, 42, 0.85)"
                      stroke="rgba(255,255,255,0.12)"
                      strokeWidth={0.75}
                    />

                    {/* Node Label Text */}
                    <text
                      x={node.size + 12}
                      y={4}
                      fill={isCampaign ? "#FDA4AF" : "#E2E8F0"}
                      fontSize={isCampaign ? 11 : 9.5}
                      fontWeight={isCampaign ? 700 : 500}
                      fontFamily="system-ui, -apple-system, sans-serif"
                      style={{ pointerEvents: "none" }}
                    >
                      {labelText}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Node Inspector Overlay (Top-Right Canvas) */}
          {selectedNode && (
            <div
              style={{
                position: "absolute",
                top: "16px",
                right: "16px",
                width: "280px",
                backgroundColor: "rgba(15, 23, 42, 0.92)",
                backdropFilter: "blur(8px)",
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: "8px",
                padding: "14px",
                fontSize: "0.78rem",
                boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <span style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700, backgroundColor: selectedNode.color, color: "#000" }}>
                  {selectedNode.type.toUpperCase()}
                </span>
                <span style={{ fontSize: "0.68rem", color: "#64748B", fontFamily: "'JetBrains Mono', monospace" }}>
                  {selectedNode.id}
                </span>
              </div>

              <div style={{ fontWeight: 700, color: "#F8FAFC", marginBottom: "6px", lineHeight: 1.3 }}>
                {selectedNode.label}
              </div>

              {selectedNode.sender && (
                <div style={{ color: "#94A3B8", marginBottom: "4px" }}>
                  From: <code style={{ color: "#38BDF8" }}>{selectedNode.sender}</code>
                </div>
              )}
              {selectedNode.origin_ip && (
                <div style={{ color: "#94A3B8", marginBottom: "4px" }}>
                  Origin IP: <code style={{ color: "#F59E0B" }}>{selectedNode.origin_ip}</code>
                </div>
              )}
              {selectedNode.domain && (
                <div style={{ color: "#94A3B8", marginBottom: "4px" }}>
                  Domain: <code style={{ color: "#34D399" }}>{selectedNode.domain}</code>
                </div>
              )}

              <div style={{ fontSize: "0.70rem", color: "#64748B", marginTop: "10px", borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: "6px" }}>
                Connected within Phishing Pot Correlation Graph
              </div>
            </div>
          )}

          {/* Bottom Help Tip */}
          <div style={{ position: "absolute", bottom: "14px", left: "16px", fontSize: "0.72rem", color: "#64748B", pointerEvents: "none" }}>
            Click node to inspect • Drag canvas to pan • Use zoom buttons to scale graph
          </div>
        </div>
      </div>
    </div>
  );
};
