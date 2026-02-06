// src/dast/crawler.js
// Web crawler for discovering forms and input parameters

const { withBrowser } = require('./browser');
const validator = require('./validator');

class Crawler {
  constructor() {
    this.maxPages = 10; // Limit pages to stay within timeout
    this.maxDepth = 2;
    this.timeout = 30000; // 30s budget for crawling
  }

  /**
   * Crawl target URL and extract forms
   * @param {string} targetUrl - Base URL to crawl
   * @param {Object} options - { maxPages, maxDepth, timeout }
   * @returns {Promise<Object>} { forms: [], pages: [], errors: [] }
   */
  async crawl(targetUrl, options = {}) {
    const maxPages = options.maxPages || this.maxPages;
    const maxDepth = options.maxDepth || this.maxDepth;
    const timeout = options.timeout || this.timeout;

    console.log(`Crawling ${targetUrl} (max ${maxPages} pages, depth ${maxDepth})...`);

    // Validate target before crawling
    validator.validateTarget(targetUrl);

    const startTime = Date.now();
    const visited = new Set();
    const toVisit = [{ url: targetUrl, depth: 0 }];
    const forms = [];
    const pages = [];
    const errors = [];

    return await withBrowser(async (browserManager) => {
      while (toVisit.length > 0 && visited.size < maxPages) {
        // Check timeout
        if (Date.now() - startTime > timeout) {
          console.warn('⚠️  Crawler timeout, returning partial results');
          break;
        }

        const { url, depth } = toVisit.shift();

        // Skip if already visited or out of scope
        if (visited.has(url) || !validator.isInScope(url, targetUrl)) {
          continue;
        }

        visited.add(url);

        try {
          const pageData = await browserManager.withPage(async (page) => {
            return await this.scrapePage(page, url, targetUrl, depth, maxDepth);
          });

          pages.push({ url, depth, success: true });
          forms.push(...pageData.forms);

          // Add discovered links to visit queue
          if (depth < maxDepth) {
            for (const link of pageData.links) {
              if (!visited.has(link) && validator.isInScope(link, targetUrl)) {
                toVisit.push({ url: link, depth: depth + 1 });
              }
            }
          }
        } catch (error) {
          console.error(`Error crawling ${url}:`, error.message);
          errors.push({ url, error: error.message });
          pages.push({ url, depth, success: false, error: error.message });
        }
      }

      console.log(`✓ Crawl complete: ${visited.size} pages, ${forms.length} forms`);

      return {
        forms,
        pages,
        errors,
        metadata: {
          pagesVisited: visited.size,
          formsFound: forms.length,
          crawlDuration: Date.now() - startTime
        }
      };
    });
  }

  /**
   * Scrape a single page for forms and links
   */
  async scrapePage(page, url, baseUrl, depth, maxDepth) {
    console.log(`  [${depth}] Scraping ${url}...`);

    // Navigate to page
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 10000
    });

    // Extract forms
    const forms = await page.evaluate(() => {
      const formElements = Array.from(document.querySelectorAll('form'));
      
      return formElements.map((form, formIndex) => {
        // Get form action (resolve relative URLs)
        let action = form.action || window.location.href;
        
        // Get form method
        const method = (form.method || 'GET').toUpperCase();

        // Extract all input fields
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

    // Extract links (for further crawling)
    const links = depth < maxDepth ? await page.evaluate((base) => {
      const linkElements = Array.from(document.querySelectorAll('a[href]'));
      const baseUrl = new URL(base);
      
      return linkElements
        .map(a => {
          try {
            const url = new URL(a.href, base);
            // Only same-origin links
            if (url.origin === baseUrl.origin) {
              return url.href;
            }
          } catch (e) {
            // Invalid URL
          }
          return null;
        })
        .filter(Boolean);
    }, baseUrl) : [];

    console.log(`    Found ${forms.length} forms, ${links.length} links`);

    return { forms, links };
  }

  /**
   * Quick scan - just the target page (no crawling)
   * Useful for testing or time-constrained scans
   */
  async quickScan(targetUrl) {
    console.log(`Quick scan: ${targetUrl}...`);
    validator.validateTarget(targetUrl);

    return await withBrowser(async (browserManager) => {
      return await browserManager.withPage(async (page) => {
        const { forms } = await this.scrapePage(page, targetUrl, targetUrl, 0, 0);
        
        return {
          forms,
          pages: [{ url: targetUrl, depth: 0, success: true }],
          errors: [],
          metadata: {
            pagesVisited: 1,
            formsFound: forms.length,
            mode: 'quick'
          }
        };
      });
    });
  }
}

module.exports = new Crawler();