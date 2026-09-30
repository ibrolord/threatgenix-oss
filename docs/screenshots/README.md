# README screenshots

The PNGs show the actual ThreatGenix OSS React interface at a 1440 × 1000 browser viewport. All accounts, applications, findings, and API responses are synthetic fixtures from the capture script. No backend, AI provider, customer evidence, or live scanner is used. Screenshots do not demonstrate backend execution or validate the example findings.

To refresh from the repository root:

```bash
cd threatgenix/frontend
npm ci
npx playwright install chromium
npm run dev -- --host 127.0.0.1 --port 5190
```

In a second terminal at the repository root:

```bash
node scripts/docs/capture-readme.mjs
```

If Chrome is already installed, you can skip the browser download and run `TG_SCREENSHOT_BROWSER=chrome node scripts/docs/capture-readme.mjs`.

Review all three images before committing. Keep real accounts, tokens, repository details, and customer artifacts out of captures.
