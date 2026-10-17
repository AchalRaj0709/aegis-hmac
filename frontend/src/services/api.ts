import {
  ClientSummary,
  ClientCreateResponse,
  KeyRotateResponse,
  AuditLog,
  HealthStatus,
} from "../types";

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch("/health");
  return res.json();
}

export async function fetchClients(): Promise<ClientSummary[]> {
  const res = await fetch("/api/v1/admin/clients");
  return res.json();
}

export async function createClient(clientName: string): Promise<ClientCreateResponse> {
  const res = await fetch("/api/v1/admin/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_name: clientName }),
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || "Failed to create client");
  }
  return res.json();
}

export async function rotateClient(clientId: string): Promise<KeyRotateResponse> {
  const res = await fetch(`/api/v1/admin/clients/${clientId}/rotate`, {
    method: "POST",
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || "Failed to rotate key");
  }
  return res.json();
}

export async function revokeClient(clientId: string): Promise<{ message: string }> {
  const res = await fetch(`/api/v1/admin/clients/${clientId}/revoke`, {
    method: "POST",
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || "Failed to revoke key");
  }
  return res.json();
}

export async function fetchAuditLogs(limit: number = 50): Promise<AuditLog[]> {
  const res = await fetch(`/api/v1/admin/audit-logs?limit=${limit}`);
  return res.json();
}

export async function dispatchCustomRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string
): Promise<{ status: number; ok: boolean; data: any }> {
  const res = await fetch(url, {
    method,
    headers,
    body: body ? body : undefined,
  });

  let data: any;
  try {
    data = await res.json();
  } catch {
    data = await res.text();
  }

  return {
    status: res.status,
    ok: res.ok,
    data,
  };
}
