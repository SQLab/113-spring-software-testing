const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await new Promise(resolve => setTimeout(resolve, 3000));
    await page.locator('.DocSearch-Button-Placeholder').click();
    
    // Type into search box
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input','andy popoo');
    
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    await new Promise(resolve => setTimeout(resolve, 3000));
    const element = await page.waitForSelector('#docsearch-hits1-item-4');
    await element.click();

    // Locate the title
    await new Promise(resolve => setTimeout(resolve, 3000));
    const textSelector = await page.waitForSelector('header h1');

    // Print the title
    const fullTitle = await textSelector?.evaluate(el => el.textContent);
    console.log(fullTitle);

    // Close the browser
    await browser.close();
})();