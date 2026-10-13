// Eigene Domain tsbw26m2.zen-tr.com: leitet jede Anfrage unverändert (inkl. Anmeldung) an die
// passwortgeschützte Pages-Seite weiter. Der Passwortschutz selbst liegt in functions/_middleware.js.
// Grund: Workers-Domains legen DNS-Eintrag und Zertifikat automatisch an, Pages-Domains nicht per wrangler.
const ORIGIN = "https://tsbw-modul2-sicherheit.pages.dev";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const res = await fetch(new Request(new URL(url.pathname + url.search, ORIGIN), request), { redirect: "manual" });
    const location = res.headers.get("Location");
    if (!location || !location.startsWith(ORIGIN)) return res;
    const out = new Response(res.body, res);
    out.headers.set("Location", url.origin + location.slice(ORIGIN.length));
    return out;
  },
};
