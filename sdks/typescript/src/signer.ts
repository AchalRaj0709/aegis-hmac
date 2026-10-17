/**
 * AegisHMAC Client-Side Request Signer (TypeScript).
 * Provides cross-environment HMAC-SHA256 signature generation (Node.js & Modern Browsers).
 */

import * as crypto from "crypto";
import {
  normalizeUriPath,
  buildCanonicalHeaders,
  buildCanonicalQueryString,
} from "./canonical";

export interface SignOptions {
  method: string;
  path: string;
  headers?: Record<string, string>;
  query?: string | Record<string, any>;
  body?: string | Buffer | Uint8Array | null;
  timestamp?: string;
  nonce?: string;
  headersToSign?: string[];
}

export class HMACSigner {
  readonly clientId: string;
  readonly secretKey: string;
  readonly algorithm: string;

  constructor(
    clientId: string,
    secretKey: string,
    algorithm: "HMAC-SHA256" | "HMAC-SHA512" = "HMAC-SHA256"
  ) {
    this.clientId = clientId.trim();
    this.secretKey = secretKey.trim();
    this.algorithm = algorithm;
  }

  private hashPayload(payload?: string | Buffer | Uint8Array | null): string {
    const hash = crypto.createHash("sha256");
    if (payload) {
      hash.update(payload);
    } else {
      hash.update("");
    }
    return hash.digest("hex");
  }

  private computeHmac(message: string): string {
    const key = this.secretKey;
    const keyBuf =
      key.length === 64 && /^[0-9a-fA-F]+$/.test(key)
        ? Buffer.from(key, "hex")
        : Buffer.from(key, "utf-8");

    const algo = this.algorithm === "HMAC-SHA256" ? "sha256" : "sha512";
    return crypto.createHmac(algo, keyBuf).update(message, "utf-8").digest("hex");
  }

  /**
   * Produce signed headers ready to attach to an HTTP request.
   */
  public sign(options: SignOptions): Record<string, string> {
    const now = new Date();
    // Compact UTC timestamp: YYYYMMDDTHHMMSSZ
    const timestamp =
      options.timestamp ||
      now
        .toISOString()
        .replace(/[-:]/g, "")
        .replace(/\.\d{3}/, "");

    const nonce = options.nonce || crypto.randomBytes(16).toString("hex");

    const headers: Record<string, string> = { ...(options.headers || {}) };
    headers["x-timestamp"] = timestamp;
    headers["x-nonce"] = nonce;

    if (options.body && !headers["content-type"]) {
      headers["content-type"] = "application/json";
    }

    const { canonicalHeaders, signedHeaders, cleanedHeaders } = buildCanonicalHeaders(
      headers,
      options.headersToSign
    );

    const canonicalUri = normalizeUriPath(options.path);
    const canonicalQs = buildCanonicalQueryString(options.query || "");
    const payloadHash = this.hashPayload(options.body);

    const canonicalParts = [
      options.method.trim().toUpperCase(),
      canonicalUri,
      canonicalQs,
      canonicalHeaders,
      signedHeaders,
      payloadHash,
      timestamp,
      nonce,
    ];

    const canonicalRequestString = canonicalParts.join("\n");
    const signature = this.computeHmac(canonicalRequestString);

    cleanedHeaders["authorization"] = `${this.algorithm} Credential=${this.clientId}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return cleanedHeaders;
  }
}
