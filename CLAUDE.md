# TSBW Modul 2 – Sicherheit

Statische Lehrvorlage (index.html, PWA-Manifest, Icons). Kein Build-Schritt.

## Deployment

- Cloudflare Pages, Projekt `tsbw-modul2-sicherheit`, mit diesem GitHub-Repo verbunden.
- Jeder Push auf `main` wird automatisch veröffentlicht (ohne Build, Ausgabe = Repo-Wurzel, `functions/` wird mitgenommen).
- Adressen: `https://tsbw26m2.zen-tr.com` (eigene Domain) und `https://tsbw-modul2-sicherheit.pages.dev`.

## Passwortschutz

- `functions/_middleware.js` sperrt die ganze Seite (übernommen aus dem Cannabis-Produktnavigator). Login-Seite mit Passwortfeld, danach bleibt das Gerät per signiertem Cookie `tsbw_m2_auth` ein Jahr angemeldet. `/__logout` meldet ab.
- Ausnahme: `manifest.json` und die Icons sind frei, damit die Installation als Web-App funktioniert.
- Das Passwort steht nur im Pages-Secret `SITE_PASSWORD`. Ohne Secret antwortet die Seite mit 503.
- Passwort ändern (Eingabe durch die Eigentümerin bzw. den Eigentümer im Terminal), danach neu deployen:
  `npx wrangler@4 pages secret put SITE_PASSWORD --project-name tsbw-modul2-sicherheit`
- Modul 3 nutzt stattdessen Cloudflare Access. Dafür hat die wrangler-Anmeldung keine Rechte, deshalb hier der Passwortschutz.

## Eigene Domain

- `tsbw26m2.zen-tr.com` hängt am Worker `tsbw-modul2-domain` (`domain-proxy/`), der jede Anfrage an die pages.dev-Seite weiterreicht. Grund: Die wrangler-Anmeldung hat keine DNS-Rechte. Worker-Domains legen DNS-Eintrag und Zertifikat automatisch an, Pages-Domains nicht.
- Nur bei Änderungen am Worker neu deployen: `cd domain-proxy && npx wrangler@4 deploy`.
- Passwörter, API-Tokens und wrangler-Anmeldedaten nie in Dateien, Git oder Dokumentation ablegen.
