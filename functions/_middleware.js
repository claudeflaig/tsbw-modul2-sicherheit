// Passwortschutz für die Cloudflare-Pages-Version.
// Das Passwort kommt aus dem Pages-Secret SITE_PASSWORD. Nach der Anmeldung über die Login-Seite
// bleibt der Browser per signiertem Cookie ein Jahr angemeldet. Das Cookie ist mit dem Passwort
// signiert: Ein neues Passwort meldet automatisch alle Geräte ab.
// HTTP Basic Auth (Benutzername beliebig) wird weiter angenommen, z. B. für curl.
// Ohne gesetztes Secret bleibt die gesamte Seite gesperrt (fail closed).

const PRIVATE_HEADERS = {
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const COOKIE = "tsbw_m2_auth";
const MAX_AGE = 365 * 24 * 60 * 60; // Sekunden
const LOGIN_PATH = "/__login";
const LOGOUT_PATH = "/__logout";
// Für die Installation als Web-App (Manifest und Icons werden ohne Cookie geladen).
const PUBLIC = new Set(["/manifest.json", "/icon.svg", "/icon-180.png", "/icon-192.png", "/icon-512.png"]);

const enc = new TextEncoder();

function deny(status, message, extra = {}) {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...PRIVATE_HEADERS, ...extra },
  });
}

async function sameSecret(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

function passwordFrom(request) {
  const [scheme, encoded] = (request.headers.get("Authorization") || "").split(" ");
  if (scheme !== "Basic" || !encoded) return null;
  try {
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)));
    const i = decoded.indexOf(":");
    return i < 0 ? null : decoded.slice(i + 1);
  } catch {
    return null;
  }
}

async function sign(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode("tsbw-m2-cookie:" + secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
  return btoa(String.fromCharCode(...mac)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeCookie(secret) {
  const exp = String(Math.floor(Date.now() / 1000) + MAX_AGE);
  const value = `${exp}.${await sign(secret, exp)}`;
  return `${COOKIE}=${value}; Max-Age=${MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

async function validCookie(request, secret) {
  const m = (request.headers.get("Cookie") || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=(\\d+)\\.([\\w-]+)`));
  if (!m || Number(m[1]) < Date.now() / 1000) return false;
  return sameSecret(m[2], await sign(secret, m[1]));
}

function safeNext(value) {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\") ? value : "/";
}

const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function loginPage(next, failed) {
  const html = `<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="color-scheme" content="light dark">
<title>Anmelden · TSBW Modul 2</title>
<style>
:root{--bg:#f6f5f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6a66;--line:#dcdad4;--accent:#3d5a80;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1f1f1d;--ink:#eceae4;--muted:#a3a19a;--line:#3a3935;--accent:#98c1d9;--err:#ff8a80}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,sans-serif}
form{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px}
h1{margin:0 0 4px;font:600 1.5rem/1.2 ui-serif,Georgia,serif}
p{margin:0 0 20px;color:var(--muted);font-size:.9rem}
label{display:block;font-size:.85rem;margin-bottom:6px}
input[type=password]{width:100%;padding:12px;font:inherit;color:inherit;background:transparent;border:1px solid var(--line);border-radius:10px}
input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{width:100%;margin-top:16px;padding:12px;font:600 1rem system-ui,sans-serif;color:#fff;background:var(--accent);border:0;border-radius:10px;cursor:pointer}
@media (prefers-color-scheme:dark){button{color:#0b0b0a}}
.err{color:var(--err);margin:12px 0 0;font-size:.9rem}
.hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
</style></head><body>
<form method="post" action="${LOGIN_PATH}">
<h1>TSBW Modul 2 – Sicherheit</h1>
<p>Privat. Dieses Gerät bleibt danach ein Jahr angemeldet.</p>
<input class="hidden" type="text" name="username" autocomplete="username" value="tsbw-modul2" tabindex="-1" aria-hidden="true">
<label for="pw">Passwort</label>
<input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>
<input type="hidden" name="next" id="next" value="${esc(next)}">
${failed ? '<p class="err" role="alert">Passwort falsch.</p>' : ""}
<button type="submit">Anmelden</button>
</form>
<script>document.getElementById("next").value+=location.hash;</script>
</body></html>`;
  return new Response(html, {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...PRIVATE_HEADERS },
  });
}

async function handleLogin(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST") return Response.redirect(new URL("/", url), 303);
  // Origin ist wegen "Referrer-Policy: no-referrer" bei Formularen "null"; deshalb Sec-Fetch-Site prüfen.
  if (request.headers.get("Sec-Fetch-Site") === "cross-site") return deny(403, "Fremde Herkunft.");
  let form;
  try {
    form = await request.formData();
  } catch {
    return deny(400, "Ungültige Anfrage.");
  }
  const next = safeNext(form.get("next"));
  const given = form.get("password");
  if (typeof given !== "string" || !(await sameSecret(given, env.SITE_PASSWORD))) return loginPage(next, true);
  return new Response(null, {
    status: 303,
    headers: { Location: next, "Set-Cookie": await makeCookie(env.SITE_PASSWORD), "Cache-Control": "no-store", ...PRIVATE_HEADERS },
  });
}

export async function onRequest({ request, env, next }) {
  if (!env.SITE_PASSWORD) return deny(503, "Seite gesperrt: Passwort ist noch nicht eingerichtet.");

  const url = new URL(request.url);
  if (PUBLIC.has(url.pathname)) return next();
  if (url.pathname === LOGIN_PATH) return handleLogin(request, env);
  if (url.pathname === LOGOUT_PATH) {
    return new Response(null, {
      status: 303,
      headers: { Location: "/", "Set-Cookie": `${COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`, "Cache-Control": "no-store", ...PRIVATE_HEADERS },
    });
  }

  let setCookie = null;
  if (!(await validCookie(request, env.SITE_PASSWORD))) {
    const given = passwordFrom(request);
    if (given === null || !(await sameSecret(given, env.SITE_PASSWORD))) {
      const isPage = request.method === "GET" && !url.pathname.startsWith("/api/") && (request.headers.get("Accept") || "").includes("text/html");
      return isPage ? loginPage(url.pathname + url.search, false) : deny(401, "Anmeldung erforderlich.");
    }
    // Bisherige Basic-Auth-Anmeldung: gleich auf das dauerhafte Cookie umstellen.
    setCookie = await makeCookie(env.SITE_PASSWORD);
  }

  const res = await next();
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(PRIVATE_HEADERS)) out.headers.set(k, v);
  if (setCookie) out.headers.append("Set-Cookie", setCookie);
  const isApi = url.pathname.startsWith("/api/");
  const isHtml = (out.headers.get("Content-Type") || "").includes("text/html");
  out.headers.set("Cache-Control", isApi ? "no-store" : isHtml ? "private, no-cache" : "private, max-age=86400");
  return out;
}
