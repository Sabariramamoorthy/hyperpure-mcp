# Hyperpure MCP

[![CI](https://github.com/karthikbala/hyperpure-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/karthikbala/hyperpure-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-hosted [Model Context Protocol](https://modelcontextprotocol.io/) server for your Hyperpure account. Search products, prepare a cart, read structured purchase history and retrieve invoices using a persistent headless Chromium browser.

**Independent community project; not affiliated with or endorsed by Hyperpure or Zomato.** Use an account you own or are authorized to operate, and follow the service's applicable terms and access limits. This project does not bypass OTP, CAPTCHA or access controls.

## Features

- Persistent login with a private page for mobile OTP renewal and an expected-outlet check.
- Product search, prices, stock, minimum quantities and verified cart updates.
- Date-filtered, paginated order history and structured quantities, discounts, taxes, fees and reconciliation.
- Credit notes, refunds, returns and reported shortages, plus original invoice and credit-note PDFs.
- Consistent history/detail delivery timestamps and account/outlet identity on every tool result.
- Authenticated Streamable HTTP for MCP and separate owner credentials for login and review.

**It never clicks Pay or submits an order.** Cart preparation and owner review are supported; final payment happens manually on Hyperpure. Refunds, returns and support tickets are read-only. One installation serves one account/outlet; this is not a multi-tenant service.

## Quick start

You need Node.js **22.9+** (22 and 24 are covered by CI), a Hyperpure account with access to its OTP phone, and an HTTPS domain reverse-proxied to the service. Linux is the documented production target. Run the browser as a non-root user with Chromium sandbox support.

```sh
git clone https://github.com/karthikbala/hyperpure-mcp.git
cd hyperpure-mcp
npm ci
npx playwright install chromium
# Linux only, if browser system dependencies are missing:
sudo npx playwright install-deps chromium
npm run configure
npm start
```

Setup asks for your HTTPS origin, mobile number, and the **exact outlet name and full delivery address** shown by Hyperpure. It generates separate random keys and writes owner-only files:

| File                        | Purpose                                                     |
| --------------------------- | ----------------------------------------------------------- |
| `.env`                      | Runtime configuration; never commit it.                     |
| `data/binding.json`         | Expected outlet identity (or your selected data directory). |
| `.secrets/owner-access.txt` | Owner page URL and unlock key.                              |
| `.secrets/connection.json`  | MCP client configuration with its bearer token.             |

Setup refuses to overwrite existing configuration. See [`.env.example`](.env.example) for configuration reference. Browser profiles and operational data must stay outside version control.

The app listens on `127.0.0.1:9310`. **HTTPS is required**, including for the secure owner cookie. Finish the [Linux deployment guide](docs/deployment.md) before opening the owner page; there is no insecure HTTP development bypass. `/healthz` reports process availability, not account login validity.

### Log in and connect

1. Open `https://YOUR_DOMAIN/owner` and unlock it with your owner key.
2. Choose **Send login OTP**, then enter the code sent by Hyperpure.
3. The service verifies the configured outlet and reports **Connected**. An address mismatch stops account operations.
4. Import `.secrets/connection.json` into an MCP client that supports Streamable HTTP with custom headers. Its shape is:

```json
{
  "mcpServers": {
    "hyperpure": {
      "url": "https://hyperpure.example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_GENERATED_MCP_TOKEN" }
    }
  }
}
```

Clients vary in configuration format. Your own deployment URL is required; there is no shared hosted endpoint. The server accepts two kinds of credentials on `/mcp`:

- **OAuth** for ChatGPT and Claude custom connectors, which cannot send a fixed header. The app registers itself and opens a consent page where you enter your **owner key** (the `/owner` unlock key) once. Access tokens last an hour and renew automatically for 90 days; clients and tokens (hashed) are kept in the data directory.
- **The generated bearer token** for clients that can send headers (Claude Code, Cursor, the Claude Desktop config file via `mcp-remote`, scripts).

**ChatGPT:** Plugins → **+** → **Add custom MCP server** → URL `https://YOUR_DOMAIN/mcp`, authentication **OAuth** (no client credentials) → **Create** → enter the owner key → **Allow access**. Mention `@Hyperpure` in a chat.

**Claude** (web, Desktop, mobile): Settings → **Connectors** → **Add custom connector** (Team/Enterprise: Organization settings → Connectors) → URL `https://YOUR_DOMAIN/mcp` → **Continue** → authentication **Sign in now**, OAuth client **Register automatically** → **Add** → enter the owner key → **Allow access**.

`node test/oauth-flow.mjs` (with `BASE` and `OWNER_KEY` set) checks the whole OAuth flow against a running server.

## Tools

| Tool                      | Purpose                                                                |
| ------------------------- | ---------------------------------------------------------------------- |
| `session_status`          | Check the live session and expected outlet.                            |
| `search_products`         | Search currently loaded account catalogue results.                     |
| `get_cart`                | Read current cart quantities, prices and total.                        |
| `set_cart_quantity`       | Set a searched product's absolute quantity; zero removes it.           |
| `list_orders`             | Filter by creation date and continue through history using cursors.    |
| `get_order`               | Read structured items, costs, credits, refunds, returns and shortages. |
| `download_invoice`        | Retrieve an account-owned order's invoice PDF.                         |
| `download_credit_notes`   | Retrieve its combined credit-note PDF when available.                  |
| `prepare_checkout_review` | Prepare a ten-minute owner review; does not purchase.                  |

JSON tools return `structuredContent` plus a compatible JSON text block. Documents are embedded PDF resources. Example history request:

```json
{ "dateFrom": "2026-01-01", "dateTo": "2026-01-31", "pageSize": 20 }
```

Continue with `{"cursor":"RETURNED_NEXT_CURSOR"}` until `pagination.nextCursor` is null, **including after an empty page**. Dates are inclusive in Asia/Kolkata and refer to order creation, not updates or refunds. For recurring checks, start a fresh scan each run and revisit older orders for late adjustments.

See [the data contract and limits](docs/data-contract.md) and [operations and troubleshooting](docs/operations.md).

## Reliability and limits

The implementation has been exercised against a live account for login persistence, search, cart changes, paginated orders, historical adjustments and PDF retrieval. CI uses synthetic, offline tests and does not log into Hyperpure. Live-account results are not a guarantee for every account or future website version.

- Hyperpure controls session expiry. Checks run every 15 minutes when idle and before operations; they do not guarantee session extension.
- OTPs are never saved or logged by this app. Requests are manual, rate-limited and isolated from background navigation.
- Uncertain cart changes are never automatically replayed. Read the cart before retrying.
- Missing fields stay `null`. Credit notes and refunds can describe the same adjustment; do not double-count them.
- Website selectors and internal read APIs can change. Errors stop the operation instead of claiming complete data.
- No built-in scheduler, outbound alert channel, off-server backup, automatic outlet switching or automatic payment is included.

## Development

```sh
npm ci
npm run check
npm run format:check
npm test
```

Offline tests cover approval expiry/replay, queue serialization, setup, pricing and units, shortages and returns, timezone boundaries and pagination integrity. No credentials or browser download are required for them.

For an optional **read-only** smoke test of your configured, logged-in deployment:

```sh
npm run test:live
```

It reads your account and may download an invoice. It does not change the cart or submit anything. Never put real account fixtures, cookies, invoices or tokens in a pull request.

## Contributing and maintenance

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), the [maintenance guide](docs/maintaining.md) and the [changelog](CHANGELOG.md). CI checks Node 22/24, syntax, tests, dependency advisories and tracked-file hygiene. Dependabot proposes dependency and GitHub Actions updates; they require review. Versioned releases document changes without promising unattended maintenance or a support SLA.

## License

[MIT](LICENSE). Third-party names and marks belong to their respective owners; the software license does not grant rights to those marks or to account data.
