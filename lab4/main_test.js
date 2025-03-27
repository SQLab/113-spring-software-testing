const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/', { waitUntil: 'domcontentloaded' });

    // Hints:
    // Click search button
    // Type into search box
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title

    // Click search button
    const buttonSelector = '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button';
    await page.waitForSelector(buttonSelector);
    await page.click(buttonSelector);

    // Type into search box
    const searchInputSelector = '#docsearch-input';
    await page.waitForSelector(searchInputSelector);
    await page.type(searchInputSelector, 'andy popoo', { delay: 100 });

    // Click
    const targetSelector = '#docsearch-hits1-item-4 > a > div > div.DocSearch-Hit-content-wrapper > span';
    await page.waitForSelector(targetSelector);
    await page.click(targetSelector);

    // Print
    const headingSelector = '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div.col.docItemCol_nDJs > div > article > div.theme-doc-markdown.markdown > header > h1';
    const pageTitle = await page.$eval(headingSelector, element => element.innerText);
    console.log(pageTitle);

    // Close the browser
    await browser.close();
})();