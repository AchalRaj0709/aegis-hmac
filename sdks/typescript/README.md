# ⚡ @aegis/client-ts

Official **TypeScript/JavaScript Client SDK** for AegisHMAC API Authentication.  
Designed for Node.js microservices and modern browser frontend applications.

---

## 📦 Installation

```bash
npm install @aegis/client-ts
```

---

## 🚀 Usage

### 1. With Native `fetch` (Browser or Node.js 18+)
```typescript
import { createHmacFetch } from "@aegis/client-ts";

const hmacFetch = createHmacFetch({
  baseUrl: "https://api.example.com",
  clientId: "client_abc123",
  secretKey: "your_256_bit_secret_key_here",
});

// Outgoing requests are automatically signed
const response = await hmacFetch("/api/v1/payments/transfer", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ recipient_id: "vendor_42", amount: 250.0 }),
});

const data = await response.json();
console.log("Transfer successful:", data);
```

---

### 2. With `Axios` via Request Interceptor
```typescript
import axios from "axios";
import { attachHmacInterceptor } from "@aegis/client-ts";

const api = axios.create({
  baseURL: "https://api.example.com",
});

// Attach automatic HMAC signing
attachHmacInterceptor(api, {
  clientId: "client_abc123",
  secretKey: "your_secret_key",
});

// All requests are now signed behind the scenes
const { data } = await api.get("/api/v1/user/profile");
console.log("Profile:", data);
```

---

### 3. Standalone `HMACSigner`
```typescript
import { HMACSigner } from "@aegis/client-ts";

const signer = new HMACSigner("client_abc123", "your_secret_key");

const signedHeaders = signer.sign({
  method: "POST",
  path: "/api/v1/webhooks/deliver",
  headers: { host: "api.example.com" },
  body: JSON.stringify({ event: "order.created" }),
});

console.log("Headers with Authorization:", signedHeaders);
```
