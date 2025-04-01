const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.click('.DocSearch.DocSearch-Button');
    await page.waitForSelector('#docsearch-input', { visible: true });
    // Type into search box
    await page.type('#docsearch-input', 'Docs', { delay: 100 });
    // Wait for search result
    await page.waitForSelector('#docsearch-list', { visible: true, timeout: 20000 });
    await new Promise(resolve => setTimeout(resolve, 1000));
    // Get the Docs result section
    // Click on first result in Docs section
    await page.waitForSelector('#docsearch-hits0-item-0', { visible: true });
    await page.click('#docsearch-hits0-item-0');
    await page.waitForFunction('document.title === "WebDriver BiDi support | Puppeteer"',{ timeout: 30000 });
    // Locate the title
    const title = await page.title();
    // Print the title
    console.log('Page Title:', title);

    // Close the browser
    await browser.close();
})();