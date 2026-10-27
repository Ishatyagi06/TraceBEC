import React, { useState, useEffect } from "react";
import { getOriginMapTrace } from "../services/api";
import {
  Globe,
  Clock,
  Search,
  AlertTriangle,
  ArrowRight,
  Copy,
  Check,
  Zap,
} from "lucide-react";

interface HopData {
  hop_number: number;
  role: string;
  ip: string;
  geo: {
    city: string;
    country: string;
    flag: string;
    lat: number;
    lng: number;
    asn: string;
    is_tor: boolean;
    is_vpn: boolean;
    org: string;
  };
  delay_seconds: number;
  risk_label: string;
  is_flagged: boolean;
}

interface OriginTraceabilityProps {
  initialIp?: string;
}

export const OriginTraceabilityMapView: React.FC<OriginTraceabilityProps> = ({ initialIp }) => {
  const [targetIp, setTargetIp] = useState<string>(initialIp || "185.220.101.45");
  const [customIp, setCustomIp] = useState<string>(initialIp || "185.220.101.45");
  const [loading, setLoading] = useState<boolean>(true);
  const [traceData, setTraceData] = useState<any>(null);
  const [activeHop, setActiveHop] = useState<HopData | null>(null);
  const [copiedIp, setCopiedIp] = useState<boolean>(false);

  useEffect(() => {
    if (initialIp && initialIp !== targetIp) {
      setTargetIp(initialIp);
      setCustomIp(initialIp);
    }
  }, [initialIp]);

  const sampleIps = [
    { ip: "185.220.101.45", label: "Tor Exit Node (Amsterdam, NL)", risk: "High", type: "Anonymizer" },
    { ip: "137.184.34.4", label: "DigitalOcean SFO3 (San Francisco, US)", risk: "Medium", type: "Cloud VPS" },
    { ip: "194.26.29.88", label: "Bulletproof VPS (Frankfurt, DE)", risk: "High", type: "Bulletproof" },
    { ip: "104.244.72.115", label: "Privacy Proxy (Reykjavik, IS)", risk: "High", type: "Proxy" },
    { ip: "51.15.24.89", label: "Scaleway Gateway (Paris, FR)", risk: "Low", type: "Corporate MX" },
  ];

  const fetchTrace = async (ip: string) => {
    try {
      setLoading(true);
      const data = await getOriginMapTrace(ip);
      setTraceData(data);
      if (data.hops && data.hops.length > 0) {
        setActiveHop(data.hops[0]);
      }
    } catch (err) {
      console.error("Failed to load origin trace:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrace(targetIp);
  }, [targetIp]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (customIp.trim()) {
      setTargetIp(customIp.trim());
    }
  };

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 2000);
  };

  // Convert GPS (lat, lng) to SVG 1000x500 coordinates
  const getCoordinates = (lat: number, lng: number) => {
    const x = ((lng + 180) / 360) * 1000;
    const y = ((90 - lat) / 180) * 500;
    return { x, y };
  };

  // Build curved bezier trajectory between hop pairs
  const renderHopArcs = () => {
    if (!traceData?.hops || traceData.hops.length < 2) return null;

    const arcs = [];
    for (let i = 0; i < traceData.hops.length - 1; i++) {
      const h1 = traceData.hops[i];
      const h2 = traceData.hops[i + 1];

      const p1 = getCoordinates(h1.geo.lat, h1.geo.lng);
      const p2 = getCoordinates(h2.geo.lat, h2.geo.lng);

      // Arc curvature offset
      const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
      const midX = (p1.x + p2.x) / 2;
      const midY = (p1.y + p2.y) / 2;
      const arcHeight = Math.min(85, Math.max(35, dist * 0.22));
      const ctrlX = midX;
      const ctrlY = midY - arcHeight;

      const pathData = `M ${p1.x} ${p1.y} Q ${ctrlX} ${ctrlY} ${p2.x} ${p2.y}`;

      arcs.push(
        <g key={`arc-${i}`}>
          {/* Subtle Ambient Glow */}
          <path
            d={pathData}
            fill="none"
            stroke={i === 0 ? "rgba(190, 24, 93, 0.35)" : "rgba(99, 102, 241, 0.30)"}
            strokeWidth="5"
            strokeLinecap="round"
            opacity="0.6"
          />
          {/* Animated Route Pulse Line */}
          <path
            d={pathData}
            fill="none"
            stroke={i === 0 ? "url(#roseRouteGrad)" : "url(#indigoRouteGrad)"}
            strokeWidth="2.2"
            strokeLinecap="round"
            className="map-route-line"
          />
        </g>
      );
    }
    return arcs;
  };

  const isCurrentSamplePreset = sampleIps.some((s) => s.ip === targetIp);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }} className="fade-in">
      
      {/* 1. Header Toolbar with Deep Rose & Navy Accent */}
      <div
        className="card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
          borderLeft: "4px solid var(--accent-rose)",
          background: "linear-gradient(135deg, rgba(21, 30, 50, 0.95), rgba(17, 24, 39, 0.98))",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
            <div
              style={{
                width: "32px",
                height: "32px",
                borderRadius: "8px",
                backgroundColor: "var(--accent-rose-subtle)",
                border: "1px solid var(--accent-rose-border)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Globe size={18} color="var(--accent-rose-bright)" />
            </div>
            <div>
              <h2 style={{ fontSize: "1.25rem", fontWeight: 700, margin: 0, color: "var(--text-main)" }}>
                Origin Traceability & Geographic Transit Map
              </h2>
            </div>
          </div>
          <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", margin: 0, paddingLeft: "42px" }}>
            Reconstruct senders, intermediate relays, geolocations, autonomous systems (ASN), and transit latencies.
          </p>
        </div>

        {/* IP Search Form with Deep Rose focus ring */}
        <form onSubmit={handleSearch} style={{ display: "flex", gap: "8px", minWidth: "320px" }}>
          <div style={{ position: "relative", flex: 1 }}>
            <Search size={14} color="var(--text-dim)" style={{ position: "absolute", left: "10px", top: "11px" }} />
            <input
              type="text"
              value={customIp}
              onChange={(e) => setCustomIp(e.target.value)}
              placeholder="Query Origin IP (e.g. 185.220.101.45)..."
              style={{
                width: "100%",
                backgroundColor: "var(--bg-inset)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                padding: "8px 10px 8px 32px",
                color: "var(--text-main)",
                fontSize: "0.82rem",
                fontFamily: "'JetBrains Mono', monospace",
                outline: "none",
              }}
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="btn"
            style={{
              padding: "8px 16px",
              fontSize: "0.82rem",
              backgroundColor: "var(--accent-rose)",
              borderColor: "var(--accent-rose)",
              color: "#FFFFFF",
              boxShadow: "0 2px 10px rgba(190, 24, 93, 0.35)",
            }}
          >
            {loading ? "Tracing..." : "Trace IP"}
          </button>
        </form>
      </div>

      {/* 2. Preset Incidents with Deep Rose / Indigo Tags */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
        <span style={{ fontSize: "0.74rem", color: "var(--text-dim)", fontWeight: 600, display: "flex", alignItems: "center", gap: "4px" }}>
          <Zap size={13} color="var(--accent-rose-bright)" />
          Benchmark Scenarios:
        </span>
        {sampleIps.map((s) => {
          const isActive = targetIp === s.ip;
          return (
            <button
              key={s.ip}
              onClick={() => { setCustomIp(s.ip); setTargetIp(s.ip); }}
              style={{
                padding: "4px 11px",
                borderRadius: "999px",
                fontSize: "0.74rem",
                backgroundColor: isActive ? "var(--accent-rose-subtle)" : "rgba(255, 255, 255, 0.04)",
                border: isActive ? "1px solid var(--accent-rose-border)" : "1px solid var(--border-subtle)",
                color: isActive ? "var(--accent-rose-bright)" : "var(--text-muted)",
                cursor: "pointer",
                fontFamily: "'JetBrains Mono', monospace",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                transition: "all var(--transition-fast)",
              }}
            >
              <span
                style={{
                  width: "5px",
                  height: "5px",
                  borderRadius: "50%",
                  backgroundColor: isActive ? "var(--accent-rose-bright)" : "var(--text-dim)",
                }}
              />
              <span>{s.ip}</span>
              <span style={{ color: "var(--text-dim)", fontSize: "0.68rem" }}>({s.label.split("(")[0].trim()})</span>
            </button>
          );
        })}
      </div>

      {/* 3. Main Interactive Map & Route Telemetry Panel */}
      <div style={{ display: "grid", gridTemplateColumns: "1.9fr 1.1fr", gap: "20px" }}>
        
        {/* World Map Canvas */}
        <div
          className="card"
          style={{
            position: "relative",
            minHeight: "480px",
            backgroundColor: "#070B14",
            border: "1px solid var(--border-subtle)",
            padding: 0,
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            boxShadow: "0 8px 30px rgba(0, 0, 0, 0.55)",
          }}
        >
          {/* Top Route Status Ribbon */}
          <div
            style={{
              padding: "12px 18px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              backgroundColor: "rgba(11, 15, 25, 0.75)",
              backdropFilter: "blur(8px)",
              zIndex: 10,
            }}
          >
            <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--accent-rose)" }} />
                <span>Origin Client:</span>
                <strong style={{ color: "var(--accent-rose-bright)", fontFamily: "'JetBrains Mono', monospace" }}>
                  {targetIp}
                </strong>
              </span>
              <ArrowRight size={12} color="var(--text-dim)" />
              <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "#10B981" }} />
                <span>Destination:</span>
                <strong style={{ color: "#34D399", fontFamily: "'JetBrains Mono', monospace" }}>
                  Corporate MX
                </strong>
              </span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              {isCurrentSamplePreset && (
                <span
                  style={{
                    fontSize: "0.68rem",
                    padding: "2px 8px",
                    borderRadius: "4px",
                    backgroundColor: "rgba(190, 24, 93, 0.12)",
                    color: "var(--accent-rose-bright)",
                    border: "1px solid var(--accent-rose-border)",
                    fontWeight: 600,
                  }}
                >
                  Benchmark Sample
                </span>
              )}
              <span className="tag tag-muted" style={{ fontSize: "0.68rem", fontFamily: "'JetBrains Mono', monospace" }}>
                WGS-84 Projection
              </span>
            </div>
          </div>

          {/* SVG Map Canvas with Realistic World Map Silhouettes & Trajectory Arcs */}
          <div style={{ flex: 1, position: "relative", width: "100%", minHeight: "420px" }}>
            <svg
              width="100%"
              height="100%"
              viewBox="0 0 1000 500"
              preserveAspectRatio="xMidYMid slice"
              style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}
            >
              <defs>
                {/* Background Tech Grid */}
                <pattern id="mapGrid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255, 255, 255, 0.025)" strokeWidth="0.5" />
                </pattern>

                {/* Deep Rose Route Gradient */}
                <linearGradient id="roseRouteGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#BE185D" />
                  <stop offset="50%" stopColor="#F472B6" />
                  <stop offset="100%" stopColor="#6366F1" />
                </linearGradient>

                {/* Indigo to Emerald Route Gradient */}
                <linearGradient id="indigoRouteGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#6366F1" />
                  <stop offset="50%" stopColor="#38BDF8" />
                  <stop offset="100%" stopColor="#10B981" />
                </linearGradient>

                {/* Subtle Glow Filter */}
                <filter id="glowFilter" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Base Navy Background */}
              <rect width="1000" height="500" fill="#070B14" />
              <rect width="1000" height="500" fill="url(#mapGrid)" />

              {/* Latitude & Longitude Reference Graticules */}
              <g stroke="rgba(255, 255, 255, 0.04)" strokeWidth="0.75" strokeDasharray="3 3">
                {/* Equator */}
                <line x1="0" y1="250" x2="1000" y2="250" stroke="rgba(190, 24, 93, 0.15)" />
                {/* Tropics */}
                <line x1="0" y1="185" x2="1000" y2="185" />
                <line x1="0" y1="315" x2="1000" y2="315" />
                {/* Prime Meridian */}
                <line x1="500" y1="0" x2="500" y2="500" stroke="rgba(99, 102, 241, 0.15)" />
                {/* Longitudes */}
                <line x1="250" y1="0" x2="250" y2="500" />
                <line x1="750" y1="0" x2="750" y2="500" />
              </g>

              {/* Realistic World Continents Silhouettes */}
              <g fill="rgba(21, 30, 50, 0.9)" stroke="rgba(99, 102, 241, 0.22)" strokeWidth="0.85">
                {/* North America */}
                <path d="M 85 70 Q 150 50 220 50 Q 280 40 320 80 Q 290 140 260 180 Q 240 230 220 270 Q 190 280 180 260 Q 170 230 140 210 Q 110 180 90 130 Z M 190 40 Q 240 30 280 50 Q 250 80 200 60 Z" />
                
                {/* Central America & Caribbean */}
                <path d="M 210 270 Q 230 290 250 305 Q 260 315 270 310 Q 250 285 220 270 Z" />
                <circle cx="280" cy="270" r="4" />
                <circle cx="295" cy="280" r="3" />

                {/* South America */}
                <path d="M 265 310 Q 330 310 350 360 Q 360 410 330 450 Q 300 485 275 480 Q 255 440 250 380 Q 250 330 265 310 Z" />

                {/* Europe */}
                <path d="M 455 75 Q 490 65 520 80 Q 555 70 560 110 Q 550 145 520 160 Q 480 170 460 150 Q 440 120 455 75 Z" />
                {/* UK & Ireland */}
                <path d="M 440 90 Q 455 85 450 115 Q 435 120 440 90 Z" />
                <circle cx="430" cy="105" r="5" />
                {/* Scandinavia */}
                <path d="M 480 45 Q 520 35 530 75 Q 500 95 480 80 Z" />
                {/* Iceland */}
                <circle cx="395" cy="65" r="6" />

                {/* Africa */}
                <path d="M 460 170 Q 545 160 565 220 Q 580 280 560 360 Q 520 420 480 410 Q 445 350 440 270 Q 440 210 460 170 Z" />
                {/* Madagascar */}
                <path d="M 585 340 Q 595 350 590 380 Q 580 385 585 340 Z" />

                {/* Asia */}
                <path d="M 560 70 Q 650 50 780 60 Q 860 70 870 140 Q 850 200 810 240 Q 750 260 700 230 Q 640 240 600 200 Q 560 160 560 70 Z" />
                {/* India / South Asia */}
                <path d="M 660 190 Q 710 190 715 250 Q 685 290 665 260 Q 650 220 660 190 Z" />
                {/* Southeast Asia */}
                <path d="M 750 220 Q 790 230 780 280 Q 750 290 740 250 Z" />
                {/* Japan */}
                <path d="M 870 120 Q 885 130 875 165 Q 860 150 870 120 Z" />

                {/* Australia */}
                <path d="M 770 330 Q 850 320 870 370 Q 860 420 810 435 Q 760 410 760 360 Z" />
                {/* New Zealand */}
                <path d="M 890 410 Q 905 415 895 445 Z" />
              </g>

              {/* Curved Animated Trajectory Arcs */}
              {renderHopArcs()}

              {/* Hop Geo Markers & Pulsing Nodes */}
              {traceData?.hops?.map((hop: HopData, idx: number) => {
                const { x, y } = getCoordinates(hop.geo.lat, hop.geo.lng);
                const isSelected = activeHop?.hop_number === hop.hop_number;
                const isOrigin = hop.hop_number === 1;
                const isDestination = hop.hop_number === traceData.hops.length;

                // Color coding: Origin = Deep Rose, Intermediate = Indigo, Destination = Emerald
                const nodeColor = isOrigin
                  ? "#BE185D"
                  : isDestination
                  ? "#10B981"
                  : "#6366F1";

                const glowColor = isOrigin
                  ? "#F472B6"
                  : isDestination
                  ? "#34D399"
                  : "#818CF8";

                return (
                  <g
                    key={idx}
                    transform={`translate(${x}, ${y})`}
                    onClick={() => setActiveHop(hop)}
                    style={{ cursor: "pointer" }}
                  >
                    {/* Pulsing Beacon Ring for Selected Node */}
                    {isSelected && (
                      <circle
                        r="22"
                        fill="none"
                        stroke={glowColor}
                        strokeWidth="1.75"
                        className="map-beacon-ring"
                      />
                    )}

                    {/* Outer Ambient Aura */}
                    <circle
                      r={isSelected ? "14" : isOrigin ? "11" : "9"}
                      fill={isOrigin ? "rgba(190, 24, 93, 0.25)" : "rgba(99, 102, 241, 0.20)"}
                      stroke={nodeColor}
                      strokeWidth={isSelected ? "2" : "1.2"}
                      filter="url(#glowFilter)"
                    />

                    {/* Core Solid Node */}
                    <circle
                      r={isSelected ? "6" : isOrigin ? "5.5" : "4.5"}
                      fill={glowColor}
                      className={isOrigin ? "map-origin-node" : ""}
                    />

                    {/* City & Hop Pill Tag */}
                    <g transform="translate(0, -14)">
                      <rect
                        x="-45"
                        y="-14"
                        width="90"
                        height="16"
                        rx="4"
                        fill="rgba(11, 15, 25, 0.88)"
                        stroke={isSelected ? glowColor : "rgba(255, 255, 255, 0.15)"}
                        strokeWidth="0.8"
                      />
                      <text
                        x="0"
                        y="-3"
                        fill={isSelected ? "#FFFFFF" : "#CBD5E1"}
                        fontSize="9"
                        fontWeight="700"
                        textAnchor="middle"
                        fontFamily="'Inter', sans-serif"
                        style={{ pointerEvents: "none" }}
                      >
                        {isOrigin ? "1: " : `${hop.hop_number}: `}{hop.geo.city}
                      </text>
                    </g>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* 4. Telemetry Inspection Panel (Deep Rose & Slate) */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          
          {/* Selected Hop Deep-Dive Card */}
          {activeHop ? (
            <div
              className="card"
              style={{
                borderLeft: `4px solid ${
                  activeHop.hop_number === 1
                    ? "var(--accent-rose)"
                    : activeHop.is_flagged
                    ? "#F43F5E"
                    : "#6366F1"
                }`,
                background: "linear-gradient(135deg, rgba(21, 30, 50, 0.95), rgba(17, 24, 39, 0.98))",
              }}
            >
              {/* Hop Header & Role */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <span
                  style={{
                    fontSize: "0.72rem",
                    fontWeight: 700,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    padding: "3px 8px",
                    borderRadius: "4px",
                    backgroundColor:
                      activeHop.hop_number === 1
                        ? "var(--accent-rose-subtle)"
                        : "rgba(99, 102, 241, 0.15)",
                    color:
                      activeHop.hop_number === 1
                        ? "var(--accent-rose-bright)"
                        : "#A5B4FC",
                    border: `1px solid ${
                      activeHop.hop_number === 1
                        ? "var(--accent-rose-border)"
                        : "rgba(99, 102, 241, 0.3)"
                    }`,
                  }}
                >
                  {activeHop.hop_number === 1 ? "ORIGIN HOP 1 OF 3" : `TRANSIT HOP ${activeHop.hop_number} OF 3`}
                </span>

                <span style={{ fontSize: "0.74rem", color: "var(--text-dim)", fontFamily: "'JetBrains Mono', monospace" }}>
                  {activeHop.role}
                </span>
              </div>

              {/* Flag + Location & IP */}
              <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "14px" }}>
                <span style={{ fontSize: "2rem", lineHeight: 1 }}>{activeHop.geo.flag}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h3 style={{ fontSize: "1.15rem", fontWeight: 700, margin: 0, color: "var(--text-main)" }}>
                    {activeHop.geo.city}, {activeHop.geo.country}
                  </h3>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "3px" }}>
                    <code style={{ fontSize: "0.84rem", color: "var(--accent-rose-bright)", fontWeight: 600 }}>
                      {activeHop.ip}
                    </code>
                    <button
                      onClick={() => handleCopyIp(activeHop.ip)}
                      style={{
                        background: "none",
                        border: "none",
                        color: "var(--text-dim)",
                        cursor: "pointer",
                        padding: "2px",
                      }}
                      title="Copy IP"
                    >
                      {copiedIp ? <Check size={12} color="#2DD4BF" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Telemetry Key-Value Grid */}
              <div
                style={{
                  backgroundColor: "var(--bg-inset)",
                  padding: "12px 14px",
                  borderRadius: "var(--radius-sm)",
                  border: "1px solid var(--border-subtle)",
                  fontSize: "0.80rem",
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "10px",
                  marginBottom: "12px",
                }}
              >
                <div>
                  <div style={{ fontSize: "0.70rem", color: "var(--text-dim)", textTransform: "uppercase" }}>Autonomous System</div>
                  <div style={{ color: "var(--text-main)", fontWeight: 500, marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                    {activeHop.geo.asn}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: "0.70rem", color: "var(--text-dim)", textTransform: "uppercase" }}>Transit Latency</div>
                  <div style={{ color: "var(--text-main)", fontWeight: 500, marginTop: "2px" }}>
                    +{activeHop.delay_seconds}s from client
                  </div>
                </div>

                <div style={{ gridColumn: "span 2" }}>
                  <div style={{ fontSize: "0.70rem", color: "var(--text-dim)", textTransform: "uppercase" }}>Network Provider</div>
                  <div style={{ color: "var(--text-muted)", marginTop: "2px", fontSize: "0.78rem" }}>
                    {activeHop.geo.org}
                  </div>
                </div>
              </div>

              {/* Anonymizer / Tor Notice (Balanced, Accurate Disclaimer) */}
              {activeHop.geo.is_tor && (
                <div
                  style={{
                    padding: "10px 12px",
                    backgroundColor: "var(--accent-rose-subtle)",
                    border: "1px solid var(--accent-rose-border)",
                    borderRadius: "var(--radius-sm)",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "8px",
                    fontSize: "0.77rem",
                    color: "var(--accent-rose-bright)",
                    lineHeight: 1.45,
                  }}
                >
                  <AlertTriangle size={15} color="var(--accent-rose-bright)" style={{ flexShrink: 0, marginTop: "2px" }} />
                  <div>
                    <strong>Observed Tor Exit Node Match.</strong> Routing path is anonymized.
                    <div style={{ color: "var(--text-muted)", marginTop: "3px", fontSize: "0.73rem" }}>
                      Anonymization indicates obfuscation risk; it does not solely confirm fraudulent intent. Correlate with message payload and authentication headers.
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="card" style={{ textAlign: "center", color: "var(--text-dim)", padding: "32px 16px" }}>
              Select a node on the map to inspect transit telemetry.
            </div>
          )}

          {/* Chronological Transit Chain List */}
          <div className="card" style={{ flex: 1 }}>
            <div className="card-title" style={{ fontSize: "0.88rem", display: "flex", alignItems: "center", gap: "7px" }}>
              <Clock size={15} color="var(--accent-rose-bright)" />
              Chronological Relay Trajectory
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {traceData?.hops?.map((h: HopData) => {
                const isSelected = activeHop?.hop_number === h.hop_number;
                const isOrigin = h.hop_number === 1;

                return (
                  <div
                    key={h.hop_number}
                    onClick={() => setActiveHop(h)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "9px 12px",
                      borderRadius: "var(--radius-sm)",
                      backgroundColor: isSelected
                        ? isOrigin
                          ? "var(--accent-rose-subtle)"
                          : "rgba(99, 102, 241, 0.12)"
                        : "var(--bg-inset)",
                      border: isSelected
                        ? isOrigin
                          ? "1px solid var(--accent-rose-border)"
                          : "1px solid var(--border-focus)"
                        : "1px solid var(--border-subtle)",
                      cursor: "pointer",
                      fontSize: "0.80rem",
                      transition: "all var(--transition-fast)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <span style={{ fontSize: "1.2rem" }}>{h.geo.flag}</span>
                      <div>
                        <div style={{ fontWeight: 600, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px" }}>
                          <span>Hop {h.hop_number}: {h.geo.city}</span>
                          {isOrigin && (
                            <span
                              style={{
                                fontSize: "0.65rem",
                                padding: "1px 5px",
                                borderRadius: "3px",
                                backgroundColor: "var(--accent-rose)",
                                color: "#FFFFFF",
                                fontWeight: 700,
                              }}
                            >
                              ORIGIN
                            </span>
                          )}
                        </div>
                        <div style={{ color: "var(--text-dim)", fontSize: "0.72rem", fontFamily: "'JetBrains Mono', monospace" }}>
                          {h.ip}
                        </div>
                      </div>
                    </div>

                    <div style={{ textAlign: "right" }}>
                      <span
                        style={{
                          fontSize: "0.72rem",
                          color: h.is_flagged ? "var(--accent-rose-bright)" : "var(--text-dim)",
                          fontWeight: 600,
                        }}
                      >
                        {h.risk_label.split(" ")[0]}
                      </span>
                      <div style={{ fontSize: "0.68rem", color: "var(--text-dim)" }}>
                        +{h.delay_seconds}s
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
