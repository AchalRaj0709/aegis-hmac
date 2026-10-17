/**
 * Browser-native Web Crypto API implementations for SHA-256 and HMAC-SHA256.
 * Zero external dependencies.
 */

function bufToHex(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export async function hashPayload(payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload || "");
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return bufToHex(hashBuffer);
}

export async function computeHmacSha256(
  secretKey: string,
  message: string
): Promise<string> {
  const encoder = new TextEncoder();
  let keyData: Uint8Array;

  // Check if hex key
  if (secretKey.length === 64 && /^[0-9a-fA-F]+$/.test(secretKey)) {
    keyData = hexToBytes(secretKey);
  } else {
    keyData = encoder.encode(secretKey);
  }

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyData as unknown as BufferSource,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(message) as unknown as BufferSource
  );

  return bufToHex(signatureBuffer);
}

export function generateRandomNonce(bytes: number = 16): string {
  const array = new Uint8Array(bytes);
  window.crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function formatCompactUtc(date: Date = new Date()): string {
  return date
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
}
