const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    // Type into search box
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title
    await page.waitForSelector('.DocSearch-Search-Icon');
    await page.click('.DocSearch-Search-Icon');
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input', 'andy popoo');
    const resultSelector = '#docsearch-hits1-item-4 > a:nth-child(1)';
    await page.waitForSelector(resultSelector);
    const resultHref = await page.$eval(resultSelector, el => el.href);
    await page.goto(resultHref, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('.theme-doc-markdown h1');
    const title = await page.$eval('.theme-doc-markdown h1', el => el.innerText);
    console.log(`${title}`);
    // Close the browser
    await browser.close();
})();