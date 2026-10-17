/**
 * AegisHMAC Native Fetch Wrapper (TypeScript).
 * Provides a drop-in replacement for window.fetch or global fetch that auto-signs requests.
 */

import { HMACSigner } from "./signer";

export interface HmacFetchConfig {
  clientId: string;
  secretKey: string;
  baseUrl?: string;
  algorithm?: "HMAC-SHA256" | "HMAC-SHA512";
}

export function createHmacFetch(config: HmacFetchConfig) {
  const signer = new HMACSigner(config.clientId, config.secretKey, config.algorithm);
  const baseUrl = config.baseUrl ? config.baseUrl.replace(/\/$/, "") : "";

  return async function hmacFetch(
    input: string | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    const rawUrl = typeof input === "string" ? input : input.toString();
    const fullUrl = rawUrl.startsWith("http") ? rawUrl : `${baseUrl}/${rawUrl.replace(/^\//, "")}`;

    const parsedUrl = new URL(fullUrl);
    const method = (init.method || "GET").toUpperCase();
    const body = init.body ? String(init.body) : null;

    const existingHeaders: Record<string, string> = {};
    if (init.headers) {
      if (init.headers instanceof Headers) {
        init.headers.forEach((val, key) => {
          existingHeaders[key] = val;
        });
      } else if (Array.isArray(init.headers)) {
        init.headers.forEach(([key, val]) => {
          existingHeaders[key] = val;
        });
      } else {
        Object.assign(existingHeaders, init.headers);
      }
    }

    if (!existingHeaders["host"]) {
      existingHeaders["host"] = parsedUrl.host;
    }

    const signedHeaders = signer.sign({
      method,
      path: parsedUrl.pathname,
      query: parsedUrl.search,
      headers: existingHeaders,
      body,
    });

    return fetch(fullUrl, {
      ...init,
      headers: signedHeaders,
    });
  };
}
