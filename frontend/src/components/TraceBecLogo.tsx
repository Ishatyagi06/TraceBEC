import React from "react";

interface TraceBecLogoProps {
  size?: "sm" | "md" | "lg";
  showTagline?: boolean;
}

export const TraceBecLogo: React.FC<TraceBecLogoProps> = ({
  size = "md",
  showTagline = true,
}) => {
  const iconSizes = {
    sm: { width: 28, height: 32 },
    md: { width: 34, height: 38 },
    lg: { width: 44, height: 50 },
  };

  const { width, height } = iconSizes[size];

  return (
    <div className="tracebec-brand" style={{ display: "flex", alignItems: "center", gap: "12px", userSelect: "none" }}>
      {/* Animated Shield + Trace Icon */}
      <div
        className="tracebec-icon-wrapper"
        style={{
          position: "relative",
          width,
          height,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <svg
          width={width}
          height={height}
          viewBox="0 0 36 42"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="tracebec-shield-svg"
        >
          <defs>
            <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#BE185D" stopOpacity="0.25" />
              <stop offset="50%" stopColor="#6366F1" stopOpacity="0.20" />
              <stop offset="100%" stopColor="#14B8A6" stopOpacity="0.12" />
            </linearGradient>
            <linearGradient id="shieldBorder" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#F472B6" />
              <stop offset="30%" stopColor="#BE185D" />
              <stop offset="65%" stopColor="#6366F1" />
              <stop offset="100%" stopColor="#2DD4BF" />
            </linearGradient>
            <linearGradient id="traceLineGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#F472B6" />
              <stop offset="50%" stopColor="#6366F1" />
              <stop offset="100%" stopColor="#2DD4BF" />
            </linearGradient>
            <linearGradient id="scanBeamGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#F472B6" stopOpacity="0" />
              <stop offset="50%" stopColor="#F472B6" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#BE185D" stopOpacity="0" />
            </linearGradient>
            <clipPath id="shieldClip">
              <path d="M18 2L32 7.5V18.5C32 27.5 25.8 35.5 18 39.5C10.2 35.5 4 27.5 4 18.5V7.5L18 2Z" />
            </clipPath>
          </defs>

          {/* Shield Outer Background */}
          <path
            d="M18 2L32 7.5V18.5C32 27.5 25.8 35.5 18 39.5C10.2 35.5 4 27.5 4 18.5V7.5L18 2Z"
            fill="url(#shieldGrad)"
            stroke="url(#shieldBorder)"
            strokeWidth="1.75"
            strokeLinejoin="round"
          />

          {/* Shield Clipping Group for Scanning Beam */}
          <g clipPath="url(#shieldClip)">
            {/* Subtle Scanning Line Beam */}
            <rect
              className="tracebec-scan-beam"
              x="0"
              y="0"
              width="36"
              height="8"
              fill="url(#scanBeamGrad)"
            />
          </g>

          {/* Email Envelope Trace Path */}
          <path
            d="M10 13H26V25H10V13Z"
            stroke="#94A3B8"
            strokeWidth="1.2"
            strokeDasharray="2 2"
            fill="none"
            opacity="0.6"
          />
          <path
            d="M10 14L18 20L26 14"
            stroke="url(#traceLineGrad)"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Dynamic Trace Nodes */}
          <line x1="10" y1="25" x2="18" y2="30" stroke="url(#traceLineGrad)" strokeWidth="1.5" />
          <line x1="26" y1="25" x2="18" y2="30" stroke="url(#traceLineGrad)" strokeWidth="1.5" />

          {/* Node Points with animated pulse */}
          <circle cx="10" cy="14" r="2.2" fill="#F472B6" className="tracebec-node node-1" />
          <circle cx="26" cy="14" r="2" fill="#818CF8" className="tracebec-node node-2" />
          <circle cx="18" cy="20" r="2.2" fill="#2DD4BF" className="tracebec-node node-center" />
          <circle cx="18" cy="30" r="2.5" fill="#2DD4BF" className="tracebec-node node-origin" />
        </svg>
      </div>

      {/* Polished Wordmark & Subtitle */}
      <div style={{ display: "flex", flexDirection: "column", justifyContent: "center" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
          <span
            style={{
              fontSize: size === "lg" ? "1.45rem" : size === "md" ? "1.2rem" : "1.05rem",
              fontWeight: 800,
              letterSpacing: "-0.035em",
              color: "#F8FAFC",
              fontFamily: "'Inter', sans-serif",
            }}
          >
            Trace<span style={{ color: "#2DD4BF" }}>BEC</span>
          </span>
          <span
            className="tracebec-badge"
            style={{
              fontSize: "0.62rem",
              fontWeight: 700,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              padding: "1px 6px",
              borderRadius: "4px",
              background: "linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(190, 24, 93, 0.16))",
              color: "#F472B6",
              border: "1px solid rgba(244, 114, 182, 0.32)",
            }}
          >
            SOC Platform
          </span>
        </div>

        {showTagline && (
          <span
            style={{
              fontSize: "0.68rem",
              fontWeight: 600,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              color: "#94A3B8",
              marginTop: "1px",
              fontFamily: "'Inter', sans-serif",
            }}
          >
            Business Email Compromise Intelligence
          </span>
        )}
      </div>
    </div>
  );
};
