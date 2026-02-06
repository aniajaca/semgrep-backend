// src/dast/crawler.js (WITH COOKIE INJECTION)
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
        // INJECT COOKIES BEFORE NAVIGATION
        if (Object.keys(cookies).length > 0) {
          console.log('  Injecting authentication cookies...');
          const url = new URL(targetUrl);
          const cookieObjects = Object.entries(cookies).map(([name, value]) => ({
            name,
            value: String(value),
            domain: url.hostname,
            path: '/'
          }));
          await page.setCookie(...cookieObjects);
          console.log(`  ✓ Set ${cookieObjects.length} cookies`);
        }

        const { forms } = await this.scrapePage(page, targetUrl, targetUrl, 0, 0);
        
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

  async scrapePage(page, url, baseUrl, depth, maxDepth) {
    console.log(`  [${depth}] Scraping ${url}...`);

    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 10000
    });

    const forms = await page.evaluate(() => {
      const formElements = Array.from(document.querySelectorAll('form'));
      
      return formElements.map((form, formIndex) => {
        let action = form.action || window.location.href;
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

    console.log(`    Found ${forms.length} forms`);
    return { forms, links: [] };
  }

  async crawl(targetUrl, options = {}) {
    return await this.quickScan(targetUrl, options);
  }
}

module.exports = new Crawler();
