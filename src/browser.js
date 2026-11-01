import { chromium } from 'playwright';
import { mkdir, readFile, unlink } from 'node:fs/promises';
import { SerialQueue, ServiceError, token, digest } from './core.js';
import { OrderHistory } from './order-history.js';
import { orderDetail } from './order-data.js';
import { responseIdentity } from './identity.js';

const HOME = 'https://www.hyperpure.com/';
export class HyperpureBrowser {
  queue = new SerialQueue();
  state = 'STARTING';
  lastVerifiedAt = null;
  challenge = null;
  products = new Map();
  stopping = false;
  constructor(config, store) {
    this.config = config;
    this.store = store;
    this.history = new OrderHistory(store, config.mcpToken);
  }
  async start() {
    this.identityKey = await this.store.read('identity-key', null);
    if (!this.identityKey) {
      this.identityKey = token();
      await this.store.write('identity-key', this.identityKey);
    }
    this.identityBinding = await this.store.read('binding', null);
    const apiOutlet = await this.store.read('api-outlet', null);
    if (
      apiOutlet?.outletId &&
      apiOutlet.identity ===
        digest(JSON.stringify({ outlet: this.identityBinding?.text, outletId: apiOutlet.outletId }))
    )
      this.outletId = apiOutlet.outletId;
    await mkdir(this.config.dataDir, { recursive: true, mode: 0o700 });
    this.context = await chromium.launchPersistentContext(`${this.config.dataDir}/profile`, {
      headless: true,
      // Only for containers whose runtime can't relax seccomp; isolation then relies on the container.
      chromiumSandbox: process.env.CHROMIUM_SANDBOX !== 'false',
      viewport: { width: 1440, height: 1000 },
      locale: 'en-IN',
      timezoneId: 'Asia/Kolkata',
      acceptDownloads: true,
    });
    this.page = this.context.pages()[0] || (await this.context.newPage());
    this.page.setDefaultTimeout(25000);
    this.page.setDefaultNavigationTimeout(45000);
    this.context.on('close', () => {
      this.state = 'BROWSER_UNAVAILABLE';
      if (!this.stopping) {
        console.error(JSON.stringify({ event: 'browser_disconnected' }));
        process.exit(1);
      }
    });
    await this.context.route('**/*', (route) =>
      route.request().resourceType() === 'media' ? route.abort() : route.continue(),
    );
    await this.page.goto(HOME, { waitUntil: 'domcontentloaded' });
    this.state = 'UNKNOWN';
  }
  status() {
    return {
      state: this.state,
      lastVerifiedAt: this.lastVerifiedAt,
      observedAt: new Date().toISOString(),
      loginUrl: `${this.config.publicOrigin}/owner`,
      checkout: 'Owner reviews the exact cart; final payment is completed on Hyperpure.',
    };
  }
  identity(verified = this.state === 'READY') {
    return responseIdentity({
      key: this.identityKey,
      mobile: this.config.mobile,
      binding: this.identityBinding,
      outletId: this.outletId,
      verified,
    });
  }
  async check() {
    // Active OTP flow owns the page. Health checks must never navigate it away.
    if (this.challenge && this.challenge.expiresAt > Date.now()) return this.status();
    this.challenge = null;
    try {
      await this.page.goto(HOME, { waitUntil: 'domcontentloaded' });
      const login = this.page.getByRole('button', { name: 'Login/Signup', exact: true });
      const binding = await this.store.read('binding', null);
      this.identityBinding = binding;
      if (binding) {
        const identity = this.page.locator(binding.selector);
        await identity.or(login).first().waitFor({ state: 'visible', timeout: 45000 });
        if (await login.isVisible()) this.state = 'AUTH_REQUIRED';
        else if ((await identity.innerText()).replace(/\s+/g, ' ').trim() === binding.text) {
          this.state = 'READY';
          this.lastVerifiedAt = new Date().toISOString();
        } else this.state = 'OUTLET_MISMATCH';
      } else {
        await login.waitFor({ state: 'visible' });
        this.state = 'AUTH_REQUIRED';
      }
    } catch {
      this.state = 'SITE_UNAVAILABLE';
    }
    return this.status();
  }
  async requestOtp() {
    if (this.state === 'READY') throw new ServiceError('ALREADY_LOGGED_IN');
    const now = Date.now(),
      limits = await this.store.read('otp-limits', { sent: [] });
    limits.sent = limits.sent.filter((t) => now - t < 3600_000);
    if (limits.sent.length >= 3 || now - (limits.sent.at(-1) || 0) < 90_000)
      throw new ServiceError(
        'OTP_COOLDOWN',
        'Wait before requesting another OTP (maximum three per hour).',
      );
    // Reserve the attempt before submitting: timeouts are not safe to replay.
    limits.sent.push(now);
    await this.store.write('otp-limits', limits);
    this.challenge = null;
    await this.page.goto(HOME, { waitUntil: 'domcontentloaded' });
    const saved = this.page.getByRole('button', {
      name: 'Login to see your saved addresses',
      exact: true,
    });
    const button = this.page.getByRole('button', { name: 'Login/Signup', exact: true });
    try {
      await button.click({ timeout: 5000 });
    } catch {
      if (await saved.isVisible()) await saved.click();
      else throw new ServiceError('LOGIN_PAGE_UNAVAILABLE');
    }
    const dialog = this.page.getByRole('dialog');
    await dialog.waitFor();
    await dialog.getByRole('textbox').fill(this.config.mobile);
    await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
    await dialog
      .getByRole('textbox', { name: 'Please enter OTP character 1', exact: true })
      .waitFor();
    this.challenge = { id: token(), expiresAt: now + 5 * 60_000, attempts: 0 };
    this.state = 'OTP_PENDING';
    return { challengeId: this.challenge.id, expiresAt: this.challenge.expiresAt };
  }
  async verifyOtp(id, otp) {
    const c = this.challenge;
    if (!c || id !== c.id || c.expiresAt < Date.now() || c.attempts >= 3)
      throw new ServiceError('OTP_EXPIRED', 'Request a new OTP when ready.');
    if (!/^\d{4,8}$/.test(otp)) throw new ServiceError('INVALID_OTP_FORMAT');
    c.attempts++;
    const inputs = this.page
        .getByRole('dialog')
        .getByRole('textbox', { name: /^Please enter OTP character / }),
      count = await inputs.count();
    if (count === 1) await inputs.fill(otp);
    else if (count === otp.length) {
      for (let i = 0; i < count; i++) await inputs.nth(i).fill(otp[i]);
    } else throw new ServiceError('SITE_CHANGED');
    await this.page
      .getByRole('dialog')
      .getByRole('button', { name: 'Verify', exact: true })
      .click();
    const binding = await this.store.read('binding', null);
    if (!binding) throw new ServiceError('SETUP_REQUIRED');
    try {
      await this.page.locator(binding.selector).filter({ hasText: binding.text }).waitFor();
    } catch {
      throw new ServiceError(
        'OTP_NOT_VERIFIED',
        'Code was not accepted, or the page needs attention.',
      );
    }
    this.challenge = null;
    return this.check();
  }
  async requireReady() {
    const status = await this.check();
    if (status.state !== 'READY')
      throw new ServiceError(
        status.state,
        'Account operations paused. Open the private owner page.',
      );
  }
  async search(query) {
    await this.requireReady();
    return this.searchCurrent(query);
  }
  async searchCurrent(query) {
    const input = this.page
      .getByRole('navigation', { name: 'main navigation' })
      .getByRole('textbox');
    await input.fill(query);
    await input.press('Enter');
    await this.page.waitForURL((url) => url.searchParams.get('query') === query, {
      waitUntil: 'domcontentloaded',
    });
    await this.page
      .getByRole('heading', { level: 3 })
      .first()
      .waitFor({ timeout: 45000 })
      .catch(async () => {
        const text = await this.page.locator('body').innerText();
        if (!/no (products|results|items) found/i.test(text))
          throw new ServiceError('SEARCH_UNAVAILABLE');
      });
    await this.assertOutlet();
    const products = await this.page.getByRole('heading', { level: 3 }).evaluateAll((headings) =>
      headings.slice(0, 60).flatMap((h) => {
        const card = h.parentElement?.parentElement;
        if (!card) return [];
        const text = card.innerText,
          button = card.querySelector('button'),
          quantity = card.querySelector('input');
        if (!button && !quantity) return [];
        const price = text.match(/₹([\d,.]+)/);
        return [
          {
            name: h.innerText,
            displayText: text,
            displayPrice: price ? Number(price[1].replaceAll(',', '')) : null,
            available: !(
              /Out of Stock/i.test(text) ||
              button?.disabled ||
              button?.getAttribute('aria-disabled') === 'true'
            ),
            minQuantity: Number(text.match(/Min Qty\s*(\d+)/i)?.[1] || 1),
          },
        ];
      }),
    );
    const unique = [...new Map(products.map((p) => [p.name, p])).values()];
    for (const product of unique) {
      product.productId = digest(product.name).slice(0, 24);
      this.products.set(product.productId, {
        ...product,
        query,
        expiresAt: Date.now() + 15 * 60_000,
      });
    }
    for (const [id, p] of this.products) if (p.expiresAt < Date.now()) this.products.delete(id);
    return {
      outlet: (await this.store.read('binding', {})).text,
      observedAt: new Date().toISOString(),
      sourceUrl: this.page.url(),
      scope: 'Currently loaded search results, up to 60; not the full catalogue.',
      products: unique,
    };
  }
  async assertOutlet() {
    const binding = await this.store.read('binding', null);
    if (!binding) throw new ServiceError('SETUP_REQUIRED');
    const nav = this.page.getByRole('navigation', { name: 'main navigation' });
    // The site's navigation wrapper has zero height; wait for identity text attachment.
    try {
      await nav
        .filter({ hasText: binding.parts[0] })
        .filter({ hasText: binding.parts[1] })
        .waitFor({ state: 'attached', timeout: 45000 });
    } catch {
      this.state = 'OUTLET_MISMATCH';
      throw new ServiceError('OUTLET_MISMATCH');
    }
    const text = (await nav.innerText()).replace(/\s+/g, ' ');
    if (!binding.parts.every((part) => text.includes(part))) {
      this.state = 'OUTLET_MISMATCH';
      throw new ServiceError('OUTLET_MISMATCH');
    }
  }
  async cart(skipCheck = false) {
    if (!skipCheck) await this.requireReady();
    await this.page.goto(`${HOME}buyer/cart`, { waitUntil: 'domcontentloaded' });
    await this.page
      .getByRole('heading', { level: 1 })
      .or(this.page.getByText('Your cart is empty!', { exact: true }))
      .first()
      .waitFor({ timeout: 45000 });
    await this.assertOutlet();
    const binding = await this.store.read('binding', {});
    if (await this.page.getByText('Your cart is empty!', { exact: true }).isVisible())
      return {
        outlet: binding.text,
        items: [],
        total: 0,
        summary: 'Your cart is empty!',
        observedAt: new Date().toISOString(),
      };
    const items = await this.page
      .locator('[class*="Cart_cartItemRow"]')
      .filter({ visible: true })
      .evaluateAll((rows) =>
        rows.map((row) => ({
          name: row.querySelector('.text-dark-blue')?.textContent?.trim(),
          quantity: Number(row.querySelector('input')?.value),
          displayText: row.innerText,
          lineTotal: Number(row.innerText.match(/₹([\d,.]+)/)?.[1]?.replaceAll(',', '')),
        })),
      );
    const totalText = await this.page
      .locator('[class*="Cart_totalVal"]')
      .filter({ visible: true })
      .first()
      .innerText();
    const total = Number(totalText.match(/₹([\d,.]+)/)?.[1]?.replaceAll(',', ''));
    if (
      !items.length ||
      items.some((i) => !i.name || !Number.isFinite(i.quantity) || !Number.isFinite(i.lineTotal)) ||
      !Number.isFinite(total)
    )
      throw new ServiceError('CART_PARSE_FAILED');
    const summary = await this.page
      .locator('[class*="Cart_summaryWrapper"]')
      .filter({ visible: true })
      .first()
      .innerText();
    return { outlet: binding.text, items, total, summary, observedAt: new Date().toISOString() };
  }
  async setCartItem(productId, quantity) {
    await this.requireReady();
    const product = this.products.get(productId);
    if (!product || product.expiresAt < Date.now())
      throw new ServiceError('SEARCH_REQUIRED', 'Search again to select a current product.');
    const before = await this.cart(true);
    let observed = before;
    const existing = before.items.find((i) => i.name === product.name);
    if ((existing?.quantity || 0) === quantity) return { changed: false, cart: before };
    if (quantity > 0 && quantity < product.minQuantity)
      throw new ServiceError('MINIMUM_QUANTITY', `Minimum quantity is ${product.minQuantity}.`);
    await this.store.write('cart-operation', {
      productName: product.name,
      quantity,
      status: 'IN_PROGRESS',
      startedAt: new Date().toISOString(),
    });
    let stage = 'search';
    try {
      if (!existing && quantity > 0) {
        await this.requireReady();
        const result = await this.searchCurrent(product.query);
        const current = result.products.find((p) => p.name === product.name);
        if (!current?.available) throw new ServiceError('OUT_OF_STOCK');
        if (quantity < current.minQuantity) throw new ServiceError('MINIMUM_QUANTITY');
        stage = 'open-quantity-picker';
        const card = this.page
          .getByRole('heading', { name: product.name, exact: true })
          .locator('xpath=../..');
        await card.getByRole('button', { name: /^ADD/ }).click();
        stage = 'wait-quantity-picker';
        const dialog = this.page.getByRole('dialog').filter({
          has: this.page.getByRole('heading', { name: 'Select quantity', exact: true }),
        });
        // Some products use a quantity picker; others add immediately.
        await Promise.race([dialog.waitFor(), card.getByRole('textbox').waitFor()]);
        if (await dialog.isVisible()) {
          stage = 'quantity-picker';
          await dialog.getByRole('button', { name: /^ADD/ }).click();
          // Locator actions wait for the actual input to become editable after the add.
          await dialog.getByRole('textbox').fill(String(current.minQuantity));
          await dialog.getByRole('textbox').press('Tab');
          await dialog.getByRole('img', { name: 'cross', exact: true }).click();
        }
        stage = 'read-added-item';
        observed = await this.cart(true);
      }
      stage = 'update-quantity';
      if ((observed.items.find((i) => i.name === product.name)?.quantity || 0) !== quantity) {
        const row = this.page
          .locator('[class*="Cart_cartItemRow"]')
          .filter({ visible: true })
          .filter({ has: this.page.getByText(product.name, { exact: true }) });
        const input = row.getByRole('textbox');
        // Edits are debounced: the typed value alone is not a saved quantity.
        const saving =
          quantity > 0
            ? row
                .locator('input:disabled')
                .waitFor({ state: 'attached' })
                .catch((e) => e)
            : null;
        await input.fill(String(quantity));
        await input.press('Tab');
        if (quantity === 0) await row.waitFor({ state: 'detached' });
        else {
          const result = await saving;
          if (result instanceof Error) throw result;
          await row.locator('input:not(:disabled)').waitFor({ state: 'attached' });
        }
      }
      stage = 'verify-persisted-cart';
      const after = await this.cart(true);
      if ((after.items.find((i) => i.name === product.name)?.quantity || 0) !== quantity)
        throw new ServiceError('CART_UPDATE_NOT_VERIFIED');
      await this.store.write('cart-operation', {
        productName: product.name,
        quantity,
        status: 'VERIFIED',
        finishedAt: new Date().toISOString(),
      });
      await this.store.write('checkout', null);
      return { changed: true, cart: after };
    } catch (e) {
      console.log(
        JSON.stringify({
          event: 'cart_update_failed',
          stage,
          errorType: e.name,
          errorCode: e.code,
          detail: e.message?.slice(0, 3000),
        }),
      );
      await this.store.write('cart-operation', {
        productName: product.name,
        quantity,
        status: 'REVIEW_REQUIRED',
        stage,
      });
      throw new ServiceError(
        'CART_UPDATE_NEEDS_REVIEW',
        'A cart change may have occurred. Read the current cart before deciding whether to retry.',
      );
    }
  }
  async openOrderHistory() {
    await this.requireReady();
    const responsePromise = this.page
      .waitForResponse(
        (r) => {
          const url = new URL(r.url());
          return (
            url.origin === 'https://api.hyperpure.com' &&
            url.pathname === '/consumer/order/history' &&
            url.searchParams.get('pageNumber') === '1'
          );
        },
        { timeout: 45000 },
      )
      .catch((e) => e);
    await this.page.goto(`${HOME}z/buyer/order`, { waitUntil: 'domcontentloaded' });
    const response = await responsePromise;
    if (response instanceof Error) throw new ServiceError('ORDER_HISTORY_UNAVAILABLE');
    await this.assertOutlet();
    // Preserve the browser's real API routing/version/outlet headers in memory only.
    this.orderHeaders = Object.fromEntries(
      Object.entries(await response.request().allHeaders()).filter(
        ([k]) => !k.startsWith(':') && !['host', 'content-length', 'accept-encoding'].includes(k),
      ),
    );
    const binding = await this.store.read('binding', null),
      outletId = this.orderHeaders['x-outletid'];
    if (!outletId) {
      this.state = 'OUTLET_MISMATCH';
      throw new ServiceError('OUTLET_MISMATCH');
    }
    const identity = digest(JSON.stringify({ outlet: binding.text, outletId }));
    const saved = await this.store.read('api-outlet', null);
    if (saved && saved.identity !== identity) {
      this.state = 'OUTLET_MISMATCH';
      throw new ServiceError('OUTLET_MISMATCH');
    }
    const data = await this.readOrderResponse(response);
    if (!Array.isArray(data.ListOfOrderDetail)) throw new ServiceError('ORDER_SCHEMA_CHANGED');
    await this.history.remember(data.ListOfOrderDetail, identity);
    if (!saved?.outletId) await this.store.write('api-outlet', { identity, outletId });
    this.outletId = outletId;
    this.orderBinding = identity;
    return data.ListOfOrderDetail;
  }
  async readOrderResponse(response) {
    const status = response.status();
    if (status === 401 || status === 403) {
      this.state = 'AUTH_REQUIRED';
      throw new ServiceError('AUTH_REQUIRED');
    }
    if (status === 429)
      throw new ServiceError('HYPERPURE_RATE_LIMITED', 'Pause checks and retry later.');
    if (status !== 200)
      throw new ServiceError('ORDER_SOURCE_UNAVAILABLE', `Hyperpure returned HTTP ${status}.`);
    const data = await response.json();
    if (data.error || !data.response) throw new ServiceError('ORDER_SOURCE_UNAVAILABLE');
    return data.response;
  }
  async orderApi(path, params) {
    if (!['/consumer/order/history', '/consumer/order/history/details'].includes(path))
      throw new ServiceError('INVALID_ORDER_ENDPOINT');
    const url = new URL(path, 'https://api.hyperpure.com');
    url.search = new URLSearchParams(params).toString();
    const response = await this.context.request.get(url.href, {
      headers: this.orderHeaders,
      timeout: 30000,
      maxRedirects: 0,
    });
    try {
      return await this.readOrderResponse(response);
    } finally {
      await response.dispose();
    }
  }
  async orders(args = {}) {
    const firstPage = await this.openOrderHistory();
    return this.history.list(args, {
      binding: this.orderBinding,
      firstPage,
      fetchPage: async (page) => {
        const data = await this.orderApi('/consumer/order/history', {
          pageNumber: String(page),
          pageSize: '20',
          filter: 'all',
        });
        if (!Array.isArray(data.ListOfOrderDetail)) throw new ServiceError('ORDER_SCHEMA_CHANGED');
        return data.ListOfOrderDetail;
      },
    });
  }
  async order(orderId) {
    await this.openOrderHistory();
    const index = await this.store.read('order-index', { orders: {} });
    if (index.binding !== this.orderBinding || !index.orders[orderId])
      throw new ServiceError(
        'ORDER_NOT_IN_DISCOVERED_HISTORY',
        'Use list_orders and its nextCursor to discover this account-owned order first.',
      );
    const data = await this.orderApi('/consumer/order/history/details', { orderId });
    if (String(data.OrderId) !== orderId || data.OrderNo !== index.orders[orderId].orderNumber)
      throw new ServiceError('ORDER_IDENTITY_MISMATCH');
    return orderDetail(data, index.orders[orderId]);
  }
  async invoice(orderId, documentKind = 'invoice') {
    const order = await this.order(orderId);
    const credit = documentKind === 'credit-notes';
    if (!(credit ? order.creditNoteDownloadAvailable : order.invoiceAvailable))
      throw new ServiceError(credit ? 'CREDIT_NOTE_UNAVAILABLE' : 'INVOICE_UNAVAILABLE');
    await this.page.goto(`${HOME}z/buyer/order/${orderId}`, { waitUntil: 'domcontentloaded' });
    await this.page.getByRole('tab', { name: 'Summary', exact: true }).waitFor({ timeout: 45000 });
    await this.assertOutlet();
    const label = credit ? 'Download Credit Note' : 'Download Invoice';
    const downloadPromise = this.page.waitForEvent('download', { timeout: 45000 });
    await this.page.getByText(label, { exact: true }).click();
    const download = await downloadPromise;
    if (await download.failure()) throw new ServiceError('INVOICE_DOWNLOAD_FAILED');
    const path = await download.path(),
      bytes = await readFile(path);
    if (bytes.length > 10 * 1024 * 1024 || bytes.subarray(0, 5).toString() !== '%PDF-')
      throw new ServiceError('INVALID_INVOICE_FILE');
    // Remove our completed temporary file without invoking Chromium's download cancellation path.
    await unlink(path);
    console.log(
      JSON.stringify({ event: 'order_document_read', documentKind, bytes: bytes.length }),
    );
    return { orderId, documentKind, mimeType: 'application/pdf', blob: bytes.toString('base64') };
  }
  async checkout() {
    const cart = await this.cart();
    if (!cart.items.length) throw new ServiceError('EMPTY_CART');
    await this.page
      .getByRole('button', { name: /^Checkout/ })
      .filter({ visible: true })
      .click();
    await this.page.waitForURL(`${HOME}buyer/checkout`, { waitUntil: 'domcontentloaded' });
    const payButton = this.page.getByRole('button', { name: /^Pay ₹/ }).filter({ visible: true });
    await payButton.waitFor({ timeout: 45000 });
    const checkoutText = await this.page.locator('main').innerText();
    const binding = await this.store.read('binding', {});
    if (!binding.parts.every((part) => checkoutText.includes(part.replace(/:$/, '')))) {
      this.state = 'OUTLET_MISMATCH';
      throw new ServiceError('OUTLET_MISMATCH');
    }
    const payText = await payButton.innerText();
    const payable = Number(payText.match(/₹([\d,.]+)/)?.[1]?.replaceAll(',', ''));
    if (!Number.isFinite(payable)) throw new ServiceError('CHECKOUT_PARSE_FAILED');
    const { observedAt, ...snapshot } = cart;
    return { ...snapshot, payable, checkoutText };
  }
  async close() {
    this.stopping = true;
    await this.context?.close();
  }
}
