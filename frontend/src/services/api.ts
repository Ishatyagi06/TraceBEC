/**
 * phisGuard API Client Service.
 * Connects to FastAPI Backend at http://localhost:8000/api/v1.
 */

const API_BASE_URL = "http://localhost:8000/api/v1";

export interface ObservedSignal {
  category: string;
  title: string;
  description: string;
  severity: "Informational" | "Caution" | "Warning" | "Suspicious";
  is_evidence_present: boolean;
}

export interface SafeNextStep {
  action: string;
  channel: string;
  description: string;
}

export interface RiskAssessment {
  risk_category: "LOW" | "REVIEW" | "HIGH";
  decision_threshold: number;
  calibrated_score: number;
  score_interpretation: string;
  model_version: string;
  observed_evidence: ObservedSignal[];
  unavailable_evidence: string[];
  limitations: string[];
  safe_next_steps: SafeNextStep[];
}

export interface KeyEvidenceItem {
  module: string;
  evidence_text: string;
  severity: "High" | "Warning" | "Informational";
}

export interface ForensicReport {
  decision: "Phishing" | "Legitimate" | "Uncertain";
  fraud_confidence_score: number;
  fraud_confidence_percentage: string;
  key_evidence: KeyEvidenceItem[];
  detailed_report: {
    module_wise_analysis: Record<string, any>;
    technical_indicators: Record<string, any>;
    related_emails_and_campaigns: any[];
    references_and_sources: string[];
  };
  module_1_nlp: {
    phishing_probability: number;
    suspicious_text_features: string[];
    detected_intents: string[];
    urgency_score: number;
  };
  module_2_headers: {
    authentication_results: Record<string, string>;
    header_anomalies: string[];
    sender_metadata: Record<string, any>;
    spoofing_probability: number;
  };
  module_3_origin: {
    origin_ip?: string;
    routing_path: any[];
    infrastructure_indicators: string[];
    is_suspicious_origin: boolean;
    transit_delay_anomaly: boolean;
  };
  module_4_reputation: {
    reputation_score: number;
    threat_intelligence_matches: string[];
    flagged_urls: any[];
    infrastructure_context: Record<string, any>;
  };
  module_5_campaign: {
    related_email_matches: any[];
    campaign_indicators: string[];
    potential_campaign_id?: string;
    similarity_score: number;
    supporting_evidence: string[];
  };
}

export interface InvestigationRecord {
  id: string;
  timestamp_iso: string;
  source_type: "eml_upload" | "visible_text" | "api";
  subject: string;
  sender: string;
  risk_assessment: RiskAssessment;
  parsed_email?: any;
  forensic_report?: ForensicReport;
}

export interface ExperimentSummary {
  rank: number;
  experiment_id: string;
  model_name: string;
  f1: number;
  pr_auc: number;
  brier_score: number;
  infer_latency_ms: number;
}

export interface BenchmarkReport {
  benchmark_timestamp: string;
  host_environment: any;
  dataset_profile: any;
  experiments: any[];
  comparative_analysis: {
    cluster_disjoint_ranking: ExperimentSummary[];
    latency_profile_ms: Record<string, number>;
  };
}

export async function analyzeEmlFile(file: File): Promise<InvestigationRecord> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE_URL}/analyze/eml`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(err.detail || `Upload failed: ${res.statusText}`);
  }
  return res.json();
}

export async function analyzeVisibleText(
  subject: string,
  body: string,
  sender: string = ""
): Promise<InvestigationRecord> {
  const res = await fetch(`${API_BASE_URL}/analyze/text`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subject, body, sender }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Analysis failed" }));
    throw new Error(err.detail || `Analysis failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigations(): Promise<InvestigationRecord[]> {
  const res = await fetch(`${API_BASE_URL}/investigations`);
  if (!res.ok) return [];
  return res.json();
}

export async function deleteInvestigation(id: string): Promise<boolean> {
  const res = await fetch(`${API_BASE_URL}/investigations/${id}`, {
    method: "DELETE",
  });
  return res.ok;
}

export async function getExperiments(): Promise<BenchmarkReport> {
  const res = await fetch(`${API_BASE_URL}/experiments`);
  if (!res.ok) throw new Error("Failed to fetch experiment results");
  return res.json();
}

export async function getNlpBenchmarks(): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/experiments/nlp-benchmarks`);
  if (!res.ok) throw new Error("Failed to fetch NLP benchmark results");
  return res.json();
}

export async function profileDataset(records: any[]): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/datasets/profile`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ records }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Profiling failed" }));
    throw new Error(err.detail || "Profiling error");
  }
  return res.json();
}

export async function profilePhishingPotDataset(): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/datasets/profile_phishing_pot`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to profile PhishingPot dataset" }));
    throw new Error(err.detail || "Profiling error");
  }
  return res.json();
}

export async function getCampaignGraph(campaignId: string = "camp_d5440b4df3ff", search?: string): Promise<any> {
  const params = new URLSearchParams();
  if (campaignId) params.append("campaign_id", campaignId);
  if (search) params.append("search", search);

  const res = await fetch(`${API_BASE_URL}/campaigns/graph?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load campaign graph");
  return res.json();
}

export async function getCampaignsList(): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/campaigns/list`);
  if (!res.ok) throw new Error("Failed to load campaigns list");
  return res.json();
}

export async function getOriginMapTrace(ip: string = "185.220.101.45"): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/origin-map/trace?ip=${encodeURIComponent(ip)}`);
  if (!res.ok) throw new Error("Failed to load origin trace map data");
  return res.json();
}

