/**
 * AegisHMAC Canonical Request Engine (TypeScript).
 * Implements deterministic AWS SigV4-compliant HTTP normalization.
 */

export function normalizeUriPath(path: string): string {
  if (!path) return "/";
  // Remove query or fragment if present
  const cleanPath = path.split("?")[0].split("#")[0];
  // Collapse duplicate slashes
  const collapsed = cleanPath.replace(/\/+/g, "/");
  return collapsed.startsWith("/") ? collapsed : `/${collapsed}`;
}

export function buildCanonicalQueryString(
  query: string | Record<string, any>
): string {
  if (!query) return "";

  const pairs: [string, string][] = [];

  if (typeof query === "string") {
    const searchParams = new URLSearchParams(query.replace(/^\?/, ""));
    searchParams.forEach((val, key) => {
      pairs.push([key, val]);
    });
  } else if (typeof query === "object") {
    for (const [key, val] of Object.entries(query)) {
      if (Array.isArray(val)) {
        val.forEach((subVal) => pairs.push([key, String(subVal)]));
      } else if (val !== undefined && val !== null) {
        pairs.push([key, String(val)]);
      }
    }
  }

  // Sort alphabetically by key, then value
  pairs.sort((a, b) => {
    if (a[0] === b[0]) return a[1].localeCompare(b[1]);
    return a[0].localeCompare(b[0]);
  });

  return pairs
    .map(
      ([k, v]) =>
        `${encodeURIComponent(k).replace(/%20/g, "+")} = ${encodeURIComponent(v).replace(/%20/g, "+")}`
    )
    .join("&");
}

export function buildCanonicalHeaders(
  headers: Record<string, string>,
  headersToSign?: string[]
): { canonicalHeaders: string; signedHeaders: string; cleanedHeaders: Record<string, string> } {
  const cleaned: Record<string, string> = {};

  for (const [k, v] of Object.entries(headers)) {
    const kLower = k.trim().toLowerCase();
    const vClean = String(v).trim().replace(/\s+/g, " ");
    cleaned[kLower] = vClean;
  }

  const targetKeys = headersToSign
    ? headersToSign.map((h) => h.trim().toLowerCase())
    : Object.keys(cleaned);

  const sortedSignedKeys = Array.from(new Set(targetKeys.filter((k) => k in cleaned))).sort();

  const canonicalHeadersList = sortedSignedKeys.map((k) => `${k}:${cleaned[k]}\n`);
  const canonicalHeaders = canonicalHeadersList.join("").replace(/\n$/, "");
  const signedHeaders = sortedSignedKeys.join(";");

  return { canonicalHeaders, signedHeaders, cleanedHeaders: cleaned };
}
