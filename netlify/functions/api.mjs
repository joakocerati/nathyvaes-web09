import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const J = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
const sign = (p) => crypto.createHmac("sha256", process.env.ADMIN_PASSWORD || "").update(p).digest("base64url");
const token = () => {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3 })).toString("base64url");
  return p + "." + sign(p);
};
const authed = (req) => {
  const [p, s] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!p || !s || !process.env.ADMIN_PASSWORD) return false;
  const e = sign(p);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return false;
  try { return JSON.parse(Buffer.from(p, "base64url")).exp > Date.now(); } catch { return false; }
};
const hash = (x) => crypto.createHash("sha256").update(String(x)).digest();

export default async (req) => {
  const route = new URL(req.url).pathname.replace(/^\/api\//, "");
  const store = getStore("nathyvaes");

  if (route === "login" && req.method === "POST") {
    const P = process.env.ADMIN_PASSWORD, U = process.env.ADMIN_USER || "admin";
    if (!P) return J({ error: "ADMIN_PASSWORD no configurada" }, 500);
    const b = await req.json().catch(() => ({}));
    if (String(b.u || "").trim().toLowerCase() === U.toLowerCase() && crypto.timingSafeEqual(hash(b.p || ""), hash(P)))
      return J({ token: token() });
    await new Promise((r) => setTimeout(r, 800));
    return J({ error: "credenciales" }, 401);
  }

  if (route === "config") {
    if (req.method === "GET") return J((await store.get("config", { type: "json" })) || {});
    if (req.method === "POST") {
      if (!authed(req)) return J({ error: "auth" }, 401);
      await store.setJSON("config", await req.json());
      return J({ ok: true });
    }
  }

  if (route === "clients") {
    if (!authed(req)) return J({ error: "auth" }, 401);
    if (req.method === "GET") return J((await store.get("clients", { type: "json" })) || []);
    if (req.method === "POST") {
      await store.setJSON("clients", await req.json());
      return J({ ok: true });
    }
  }

  return J({ error: "no encontrado" }, 404);
};
