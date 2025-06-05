const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.waitForSelector('.DocSearch-Button-Placeholder'); //select by class(.)
    await page.click('.DocSearch-Search-Icon');

    // Type into search box
    await page.waitForSelector('#docsearch-input'); //select by id(#)
    await page.type('#docsearch-input', 'andy popoo');

    // Wait for search result 
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    await page.waitForSelector('#docsearch-hits1-item-4 a'); //find first <a> element in child
    const resultHref = await page.$eval('#docsearch-hits1-item-4 a', el => el.href);
    await page.goto(resultHref, { waitUntil: 'domcontentloaded' });
    
    // Locate the title
    await page.waitForSelector('.theme-doc-markdown h1'); 
    const resultTitle = await page.$eval('.theme-doc-markdown h1', el => el.textContent);
    // Print the title 
    console.log(`${resultTitle}`);
    // Close the browser
    await browser.close();
})();