// src/dast/browser.js
// Isolated Puppeteer browser management for DAST (separate from Report Builder)

const puppeteer = require('puppeteer');

class BrowserManager {
  constructor() {
    this.browser = null;
    this.launchOptions = {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-zygote',
        '--single-process', // Thesis only - limits resource usage
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-background-timer-throttling',
        '--disable-renderer-backgrounding',
        '--disable-sync'
      ],
      timeout: 10000, // 10s launch timeout
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined
    };
  }

  /**
   * Launch browser instance (lazy initialization)
   * @returns {Promise<Browser>}
   */
  async launchBrowser() {
    if (!this.browser || !this.browser.isConnected()) {
      console.log('Launching Puppeteer browser...');
      this.browser = await puppeteer.launch(this.launchOptions);
      console.log('✓ Browser launched');
    }
    return this.browser;
  }

  /**
   * Create a new page with DAST-specific settings
   * @returns {Promise<Page>}
   */
  async createPage() {
    const browser = await this.launchBrowser();
    const page = await browser.newPage();

    // Set reasonable viewport
    await page.setViewport({
      width: 1280,
      height: 720
    });

    // Set user agent (identify as scanner)
    await page.setUserAgent(
      'Mozilla/5.0 (compatible; Neperia-DAST/1.0; +https://neperia.com)'
    );

    // Set timeouts
    page.setDefaultTimeout(10000); // 10s per operation
    page.setDefaultNavigationTimeout(15000); // 15s for navigation

    // Disable unnecessary resource loading (faster scans)
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const resourceType = request.resourceType();
      // Block images, fonts, media to speed up crawling
      if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
        request.abort();
      } else {
        request.continue();
      }
    });

    return page;
  }

  /**
   * Execute a scan operation with automatic cleanup
   * @param {Function} callback - Async function that receives a page
   * @returns {Promise<any>}
   */
  async withPage(callback) {
    let page = null;
    try {
      page = await this.createPage();
      return await callback(page);
    } finally {
      if (page) {
        await page.close().catch(e => console.error('Error closing page:', e));
      }
    }
  }

  /**
   * Close browser and cleanup (called after scan completes)
   * CRITICAL: Always call this to prevent resource leaks
   */
  async close() {
    if (this.browser) {
      console.log('Closing browser...');
      await this.browser.close();
      this.browser = null;
      console.log('✓ Browser closed');
    }
  }

  /**
   * Check if browser is running
   * @returns {boolean}
   */
  isRunning() {
    return this.browser && this.browser.isConnected();
  }
}

// Singleton instance
let instance = null;

/**
 * Get browser manager instance
 * @returns {BrowserManager}
 */
function getBrowserManager() {
  if (!instance) {
    instance = new BrowserManager();
  }
  return instance;
}

/**
 * Execute scan with automatic browser lifecycle management
 * @param {Function} callback - Async function that receives browser manager
 * @returns {Promise<any>}
 */
async function withBrowser(callback) {
  const manager = getBrowserManager();
  try {
    return await callback(manager);
  } finally {
    // Always cleanup browser after scan
    await manager.close();
  }
}

module.exports = {
  BrowserManager,
  getBrowserManager,
  withBrowser
};