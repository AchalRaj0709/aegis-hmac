export interface ClientSummary {
  client_id: string;
  client_name: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  active_key_version: number;
  created_at: string;
}

export interface ClientCreateResponse {
  client_id: string;
  client_name: string;
  secret_key: string;
  key_version: number;
  algorithm: string;
  created_at: string;
}

export interface KeyRotateResponse {
  client_id: string;
  new_secret_key: string;
  new_key_version: number;
  grace_period_expires_at: string;
  message: string;
}

export interface AuditLog {
  request_id: string;
  client_id?: string;
  timestamp: string;
  method: string;
  path: string;
  ip_address?: string;
  status_code: number;
  verdict: "SUCCESS" | "FAILED";
  failure_reason?: string;
  latency_ms: number;
}

export interface HealthStatus {
  status: string;
  service: string;
  environment: string;
  timestamp: string;
}
