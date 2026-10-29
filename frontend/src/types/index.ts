export interface ExtractedFeatures {
  url_length: number;
  hostname_length: number;
  path_length: number;
  count_dots: number;
  count_hyphens: number;
  count_at: number;
  count_question: number;
  count_equal: number;
  count_slash: number;
  count_digits: number;
  count_subdomains: number;
  has_ip: number;
  is_https: number;
  has_suspicious_keywords: number;
  digit_ratio: number;
  special_char_ratio: number;
  apex_domain?: string;
  is_verified_domain?: number;
  [key: string]: any;
}

export interface ThreatProviderResult {
  status: 'Not Configured' | 'No Match Reported' | 'Threat Reported' | 'Unverified Reported' | 'Unavailable' | 'Inconclusive';
  threat_found: boolean;
  category: string | null;
  details: string | null;
}

export interface ThreatIntelligenceSummary {
  openphish?: ThreatProviderResult | null;
  phishing_database?: ThreatProviderResult | null;
  phish_destroy?: ThreatProviderResult | null;
  phishstats?: ThreatProviderResult | null;
  google_safe_browsing?: ThreatProviderResult | null;
}

export interface ScanResult {
  scan_id: string;
  submitted_url: string;
  normalized_url: string;
  predicted_class: 'Legitimate' | 'Phishing';
  risk_level: 'Low Risk' | 'Suspicious' | 'High Risk';
  ml_probability: number;
  model_score: number | null;
  raw_ml_score?: number | null;
  is_verified_domain?: boolean;
  apex_domain?: string | null;
  threat_intel_match?: boolean;
  extracted_features: ExtractedFeatures;
  suspicious_reasons: string[];
  threat_intelligence: ThreatIntelligenceSummary;
  combined_interpretation: string;
  recommended_precautions: string[];
  model_version: string;
  created_at: string;
}

export interface ScanListItem {
  scan_id: string;
  submitted_url: string;
  predicted_class: 'Legitimate' | 'Phishing';
  risk_level: 'Low Risk' | 'Suspicious' | 'High Risk';
  model_score: number | null;
  created_at: string;
  threat_intel_match: boolean;
}

export interface ScanListResponse {
  total_records: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: ScanListItem[];
}

export interface ChartSlice {
  name: string;
  value: number;
  color: string;
}

export interface TemporalDataPoint {
  date: string;
  scans: number;
  phishing: number;
}

export interface AnalyticsData {
  total_scans: number;
  phishing_count: number;
  legitimate_count: number;
  high_risk_count: number;
  threat_intel_matches: number;
  threat_intel_failures: number;
  classification_distribution: ChartSlice[];
  risk_distribution: ChartSlice[];
  scans_over_time: TemporalDataPoint[];
  model_status: {
    version: string;
    algorithm: string;
    status: string;
  };
  threat_provider_status: Record<string, string>;
}

export interface ModelMetadata {
  model_version: string;
  algorithm: string;
  dataset_name: string;
  training_date: string;
  total_samples: number;
  train_samples: number;
  test_samples: number;
  train_domains?: number;
  test_domains?: number;
  domain_leakage_count?: number;
  evaluation_metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
    false_positive_rate?: number;
    false_negative_rate?: number;
    missed_threats_count?: number;
    long_tail_legit_fpr?: number;
    hard_phishing_recall?: number;
  };
  confusion_matrix: {
    tn: number;
    fp: number;
    fn: number;
    tp: number;
  };
  test_set_sizes?: {
    holdout_test?: number;
    long_tail_legit?: number;
    hard_phishing?: number;
  };
  collection_dates?: {
    training?: string;
    holdout_test?: string;
    long_tail_legit?: string;
    hard_phishing?: string;
  };
  limitations?: string[];
  feature_schema: string[];
  feature_importances: Record<string, number>;
}

export interface HealthData {
  status: string;
  database: string;
  ml_model_loaded: boolean;
  model_version: string;
  threat_providers?: Record<string, string>;
  timestamp: string;
}

export interface User {
  id: number;
  full_name: string;
  email: string;
  created_at: string;
  account_status: string;
}

export interface AuthResponse {
  user: {
    id: number;
    full_name: string;
    email: string;
    created_at: string;
    account_status: string;
  };
  csrf_token: string;
  message: string;
}
