const { withBrowser } = require('./browser');
const validator = require('./validator');

class Crawler {
  constructor() {
    this.maxPages = 10;
    this.maxDepth = 2;
    this.timeout = 30000;
  }

  async quickScan(targetUrl, options = {}) {
    console.log(`Quick scan: ${targetUrl}...`);
    validator.validateTarget(targetUrl);

    const cookies = options.cookies || {};

    return await withBrowser(async (browserManager) => {
      return await browserManager.withPage(async (page) => {
        if (Object.keys(cookies).length > 0) {
          console.log('  Injecting authentication cookies...');
          const origin = new URL(targetUrl).origin;
          const cookieObjects = Object.entries(cookies).map(([name, value]) => ({
            name,
            value: String(value),
            url: origin
          }));
          await page.setCookie(...cookieObjects);
          console.log(`  ✓ Set ${cookieObjects.length} cookies`);
        }

        await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        
        // FIX 4: Better auth verification
        if (page.url().includes('login.php')) {
          console.warn('  ⚠️  Redirected to login page - authentication failed');
        } else {
          console.log('  ✓ Authenticated successfully');
        }

        const forms = await this.extractForms(page);
        
        return {
          forms,
          pages: [{ url: targetUrl, depth: 0, success: true }],
          errors: [],
          metadata: {
            pagesVisited: 1,
            formsFound: forms.length,
            mode: 'quick',
            authenticated: Object.keys(cookies).length > 0
          }
        };
      });
    });
  }

  async extractForms(page) {
    return await page.evaluate(() => {
      const formElements = Array.from(document.querySelectorAll('form'));
      
      return formElements.map((form, formIndex) => {
        // FIX 1: Normalize to absolute URL
        const actionAttr = form.getAttribute('action') || '';
        const action = new URL(actionAttr || window.location.href, window.location.href).href;
        const method = (form.method || 'GET').toUpperCase();

        const inputs = Array.from(form.querySelectorAll('input, textarea, select')).map(input => {
          return {
            name: input.name || input.id || `unnamed_${Math.random().toString(36).substr(2, 9)}`,
            type: input.type || 'text',
            value: input.value || '',
            tagName: input.tagName.toLowerCase(),
            required: input.required || false
          };
        });

        return {
          action,
          method,
          inputs,
          formIndex,
          pageUrl: window.location.href
        };
      });
    });
  }

  async crawl(targetUrl, options = {}) {
    return await this.quickScan(targetUrl, options);
  }
}

module.exports = new Crawler();
