import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const h = (x) => crypto.createHash("sha256").update(String(x)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(h(a), h(b));
const sign = (p, sec) => crypto.createHmac("sha256", sec).update(p).digest("base64url");

export default async (req) => {
  const store = getStore("bilcoin");
  const get = async () => (await store.get("state", { type: "json" })) || { pts: {}, log: [] };
  if (req.method === "GET") return J(await get());
  if (req.method !== "POST") return J({ error: "Метод не поддерживается" }, 405);

  const sec = process.env.TOKEN_SECRET;
  if (!sec) return J({ error: "На сервере не задан TOKEN_SECRET" }, 500);
  let acc = {};
  try { acc = JSON.parse(process.env.ADMIN_ACCOUNTS || "{}"); } catch {}
  let b;
  try { b = await req.json(); } catch { return J({ error: "Неверный запрос" }, 400); }

  if (b.action === "login") {
    const ok = typeof b.user === "string" && Object.hasOwn(acc, b.user) && safeEq(acc[b.user], b.pass ?? "");
    if (!ok) { await new Promise((r) => setTimeout(r, 900)); return J({ error: "Неверный логин или пароль" }, 401); }
    const p = Buffer.from(JSON.stringify({ u: b.user, exp: Date.now() + 12 * 3600e3 })).toString("base64url");
    return J({ token: p + "." + sign(p, sec), user: b.user });
  }

  let user = null;
  const [p, s] = String(b.token || "").split(".");
  if (p && s && safeEq(sign(p, sec), s)) {
    try { const o = JSON.parse(Buffer.from(p, "base64url").toString()); if (o.exp > Date.now()) user = o.u; } catch {}
  }
  if (!user) return J({ error: "Сессия истекла, войдите снова" }, 401);

  if (b.action === "award") {
    const pt = Number(b.p);
    if (!/^(7|8|9|10|11)[АБ]-\d{1,2}$/.test(String(b.id)) || !Number.isInteger(pt) || pt === 0 || Math.abs(pt) > 10000)
      return J({ error: "Неверные данные" }, 400);
    const st = await get();
    st.pts[b.id] = (st.pts[b.id] || 0) + pt;
    st.log.push({ i: b.id, p: pt, r: String(b.r || "").slice(0, 120), t: Date.now(), by: user });
    st.log = st.log.slice(-3000);
    await store.setJSON("state", st);
    return J(st);
  }
  return J({ error: "Неизвестное действие" }, 400);
};
