import React from "react";
import { ShieldCheck, AlertTriangle, AlertOctagon } from "lucide-react";

interface TriageBadgeProps {
  category: "LOW" | "REVIEW" | "HIGH";
  score?: number;
  showScore?: boolean;
}

export const TriageBadge: React.FC<TriageBadgeProps> = ({
  category,
  score,
  showScore = true,
}) => {
  const cat = category ? category.toUpperCase() : "LOW";

  if (cat === "HIGH") {
    return (
      <span className="triage-badge high" role="status" aria-label="High Risk BEC Threat">
        <AlertOctagon size={16} />
        <span>High Risk</span>
        {showScore && score !== undefined && (
          <span style={{ opacity: 0.85, fontWeight: 500 }}>
            ({(score * 100).toFixed(1)}%)
          </span>
        )}
      </span>
    );
  }

  if (cat === "REVIEW") {
    return (
      <span className="triage-badge review" role="status" aria-label="Review Required">
        <AlertTriangle size={16} />
        <span>Review Required</span>
        {showScore && score !== undefined && (
          <span style={{ opacity: 0.85, fontWeight: 500 }}>
            ({(score * 100).toFixed(1)}%)
          </span>
        )}
      </span>
    );
  }

  return (
    <span className="triage-badge low" role="status" aria-label="Low Risk">
      <ShieldCheck size={16} />
      <span>Low Risk</span>
      {showScore && score !== undefined && (
        <span style={{ opacity: 0.85, fontWeight: 500 }}>
          ({(score * 100).toFixed(1)}%)
        </span>
      )}
    </span>
  );
};
