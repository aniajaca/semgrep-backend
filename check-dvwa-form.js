const { withBrowser } = require('./src/dast/browser');

async function checkForm() {
  await withBrowser(async (manager) => {
    await manager.withPage(async (page) => {
      // Set cookies
      await page.setCookie(
        { name: 'PHPSESSID', value: 'lforop4bmja8onpsut6kjk8655', domain: 'localhost', path: '/' },
        { name: 'security', value: 'low', domain: 'localhost', path: '/' }
      );
      
      // Navigate
      await page.goto('http://localhost:8080/vulnerabilities/sqli/', { waitUntil: 'domcontentloaded' });
      
      // Check what we got
      const pageTitle = await page.title();
      const forms = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('form')).map(f => ({
          action: f.action,
          inputs: Array.from(f.querySelectorAll('input')).map(i => i.name)
        }));
      });
      
      console.log('Page title:', pageTitle);
      console.log('Forms found:', JSON.stringify(forms, null, 2));
    });
  });
}

checkForm();
