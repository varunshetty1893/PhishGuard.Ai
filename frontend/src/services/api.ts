import type {
  ScanResult,
  ScanListResponse,
  AnalyticsData,
  ModelMetadata,
  HealthData
} from '../types';

const API_BASE = '/api/v1';

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // response is not JSON
    }
    throw new Error(errorDetail);
  }
  return response.json();
}

export const api = {
  async scanUrl(url: string): Promise<ScanResult> {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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

    const res = await fetch(url.toString());
    return handleResponse<ScanListResponse>(res);
  },

  async getScanById(scanId: string): Promise<ScanResult> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`);
    return handleResponse<ScanResult>(res);
  },

  async deleteScan(scanId: string): Promise<{ message: string; scan_id: string }> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, {
      method: 'DELETE'
    });
    return handleResponse<{ message: string; scan_id: string }>(res);
  },

  async clearAllScans(): Promise<{ message: string; deleted_count: number }> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'DELETE'
    });
    return handleResponse<{ message: string; deleted_count: number }>(res);
  },

  async getAnalytics(): Promise<AnalyticsData> {
    const res = await fetch(`${API_BASE}/analytics`);
    return handleResponse<AnalyticsData>(res);
  },

  async getModelInfo(): Promise<ModelMetadata> {
    const res = await fetch(`${API_BASE}/model/info`);
    return handleResponse<ModelMetadata>(res);
  },

  async getHealth(): Promise<HealthData> {
    const res = await fetch(`${API_BASE}/health`);
    return handleResponse<HealthData>(res);
  },

  getExportCsvUrl(): string {
    return `${API_BASE}/scans/export`;
  }
};
