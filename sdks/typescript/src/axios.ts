/**
 * AegisHMAC Axios Interceptor Plugin (TypeScript).
 * Automatically injects HMAC headers on every outbound Axios request.
 */

import { HMACSigner } from "./signer";

export interface AxiosInterceptorConfig {
  clientId: string;
  secretKey: string;
  algorithm?: "HMAC-SHA256" | "HMAC-SHA512";
}

/**
 * Attach automatic HMAC signing to an Axios instance.
 * Usage:
 *    const api = axios.create({ baseURL: "https://api.aegis.io" });
 *    attachHmacInterceptor(api, { clientId: "...", secretKey: "..." });
 */
export function attachHmacInterceptor(
  axiosInstance: any,
  config: AxiosInterceptorConfig
): void {
  const signer = new HMACSigner(config.clientId, config.secretKey, config.algorithm);

  axiosInstance.interceptors.request.use((reqConfig: any) => {
    const method = (reqConfig.method || "get").toUpperCase();
    const url = new URL(reqConfig.url, reqConfig.baseURL || "http://localhost");
    const path = url.pathname;
    const body = reqConfig.data ? (typeof reqConfig.data === "string" ? reqConfig.data : JSON.stringify(reqConfig.data)) : null;

    const existingHeaders: Record<string, string> = {};
    if (reqConfig.headers) {
      for (const [k, v] of Object.entries(reqConfig.headers)) {
        if (v !== undefined && v !== null) {
          existingHeaders[k] = String(v);
        }
      }
    }

    if (!existingHeaders["host"]) {
      existingHeaders["host"] = url.host;
    }

    const signedHeaders = signer.sign({
      method,
      path,
      query: reqConfig.params || url.search,
      headers: existingHeaders,
      body,
    });

    reqConfig.headers = { ...reqConfig.headers, ...signedHeaders };
    return reqConfig;
  });
}
