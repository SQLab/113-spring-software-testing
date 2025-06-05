const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Click search button
    await page.waitForSelector('.DocSearch-Search-Icon');
    await page.click('.DocSearch-Search-Icon');

    // Type into search box
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input', 'andy popoo');

    // Wait for search result
    const resultSelector = '#docsearch-hits1-item-4 > a:nth-child(1)';
    await page.waitForSelector(resultSelector);

    // Get the `Docs` result section
    const resultHref = await page.$eval(resultSelector, el => el.href);
    await page.goto(resultHref, { waitUntil: 'domcontentloaded' });
    // Locate the title
    await page.waitForSelector('.theme-doc-markdown h1');
    const title = await page.$eval('.theme-doc-markdown h1', el => el.innerText);
    // Print the title
    console.log(`${title}`);

    // Close the browser
    await browser.close();
})();
