import type {
  ScanResult,
  ScanListResponse,
  AnalyticsData,
  ModelMetadata,
  HealthData,
  AuthResponse
} from '../types';

const API_BASE = '/api/v1';

// Helper to extract CSRF token from document.cookie
function getCsrfTokenFromCookie(): string | null {
  const match = document.cookie.match(new RegExp('(^| )phishguard_csrf=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

let cachedCsrfToken: string | null = null;
let cachedAnalytics: { data: AnalyticsData; timestamp: number } | null = null;
const ANALYTICS_CACHE_TTL_MS = 20000; // 20 seconds cache for instant dashboard transitions

export function setCachedCsrfToken(token: string) {
  cachedCsrfToken = token;
}

export function clearAnalyticsCache() {
  cachedAnalytics = null;
}

export function getCachedAnalytics(): AnalyticsData | null {
  if (cachedAnalytics && Date.now() - cachedAnalytics.timestamp < ANALYTICS_CACHE_TTL_MS) {
    return cachedAnalytics.data;
  }
  return null;
}

function getActiveCsrfToken(): string | null {
  return cachedCsrfToken || getCsrfTokenFromCookie();
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        if (typeof errJson.detail === 'string') {
          errorDetail = errJson.detail;
        } else if (Array.isArray(errJson.detail)) {
          errorDetail = errJson.detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ');
        }
      }
    } catch {
      // response is not JSON
    }
    throw new Error(errorDetail);
  }
  return response.json();
}

function getFetchHeaders(includeJson: boolean = true, isMutating: boolean = false): Record<string, string> {
  const headers: Record<string, string> = {};
  if (includeJson) {
    headers['Content-Type'] = 'application/json';
  }
  if (isMutating) {
    const csrf = getActiveCsrfToken();
    if (csrf) {
      headers['X-CSRF-Token'] = csrf;
    }
  }
  return headers;
}

export const api = {
  // Authentication
  async register(payload: {
    full_name: string;
    email: string;
    password: string;
    confirm_password: string;
  }): Promise<{ message: string }> {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: getFetchHeaders(true, false),
      credentials: 'include',
      body: JSON.stringify(payload)
    });
    return handleResponse<{ message: string }>(res);
  },

  async login(payload: {
    email: string;
    password: string;
    remember_me?: boolean;
  }): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: getFetchHeaders(true, false),
      credentials: 'include',
      body: JSON.stringify(payload)
    });
    const data = await handleResponse<AuthResponse>(res);
    if (data.csrf_token) {
      setCachedCsrfToken(data.csrf_token);
    }
    return data;
  },

  async logout(): Promise<{ message: string }> {
    clearAnalyticsCache();
    const res = await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: getFetchHeaders(true, true),
      credentials: 'include'
    });
    cachedCsrfToken = null;
    return handleResponse<{ message: string }>(res);
  },

  async getMe(): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      method: 'GET',
      credentials: 'include'
    });
    const data = await handleResponse<AuthResponse>(res);
    if (data.csrf_token) {
      setCachedCsrfToken(data.csrf_token);
    }
    return data;
  },

  // Scanner & History
  async scanUrl(url: string): Promise<ScanResult> {
    clearAnalyticsCache();
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: getFetchHeaders(true, true),
      credentials: 'include',
      body: JSON.stringify({ url })
    });
    return handleResponse<ScanResult>(res);
  },

  async getScans(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    predicted_class?: string;
    risk_level?: string;
    threat_status?: string;
  }): Promise<ScanListResponse> {
    const url = new URL(`${API_BASE}/scans`, window.location.origin);
    if (params?.page) url.searchParams.set('page', params.page.toString());
    if (params?.page_size) url.searchParams.set('page_size', params.page_size.toString());
    if (params?.search) url.searchParams.set('search', params.search);
    if (params?.predicted_class && params.predicted_class !== 'All') {
      url.searchParams.set('predicted_class', params.predicted_class);
    }
    if (params?.risk_level && params.risk_level !== 'All') {
      url.searchParams.set('risk_level', params.risk_level);
    }
    if (params?.threat_status && params.threat_status !== 'All') {
      url.searchParams.set('threat_status', params.threat_status);
    }

    const res = await fetch(url.toString(), {
      credentials: 'include'
    });
    return handleResponse<ScanListResponse>(res);
  },

  async getScanById(scanId: string): Promise<ScanResult> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, {
      credentials: 'include'
    });
    return handleResponse<ScanResult>(res);
  },

  async deleteScan(scanId: string): Promise<{ message: string; scan_id: string }> {
    clearAnalyticsCache();
    const res = await fetch(`${API_BASE}/scans/${scanId}`, {
      method: 'DELETE',
      headers: getFetchHeaders(false, true),
      credentials: 'include'
    });
    return handleResponse<{ message: string; scan_id: string }>(res);
  },

  async clearAllScans(): Promise<{ message: string; deleted_count: number }> {
    clearAnalyticsCache();
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'DELETE',
      headers: getFetchHeaders(false, true),
      credentials: 'include'
    });
    return handleResponse<{ message: string; deleted_count: number }>(res);
  },

  // Analytics & Model
  async getAnalytics(forceRefresh: boolean = false): Promise<AnalyticsData> {
    const now = Date.now();
    if (!forceRefresh && cachedAnalytics && now - cachedAnalytics.timestamp < ANALYTICS_CACHE_TTL_MS) {
      return cachedAnalytics.data;
    }
    const res = await fetch(`${API_BASE}/analytics`, {
      credentials: 'include'
    });
    const data = await handleResponse<AnalyticsData>(res);
    cachedAnalytics = { data, timestamp: Date.now() };
    return data;
  },

  async getModelInfo(): Promise<ModelMetadata> {
    const res = await fetch(`${API_BASE}/model/info`, {
      credentials: 'include'
    });
    return handleResponse<ModelMetadata>(res);
  },

  async getHealth(): Promise<HealthData> {
    const res = await fetch(`${API_BASE}/health`, {
      credentials: 'include'
    });
    return handleResponse<HealthData>(res);
  },

  getExportCsvUrl(): string {
    return `${API_BASE}/scans/export`;
  }
};
