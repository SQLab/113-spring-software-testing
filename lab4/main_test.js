const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    await page.locator('.DocSearch-Button-Placeholder').click();

    await page.locator('.DocSearch-Input').fill('andy popoo');

    await page.locator('#docsearch-hits1-item-4').click();
    
    // Locate the full title with a unique string.
    const textSelector = await page
      .locator('text/ndDrop() method')
      .waitHandle();

    const fullTitle = await textSelector?.evaluate(el => el.textContent);
    
    // Print the full title.
    console.log(fullTitle);

    await browser.close();
})();