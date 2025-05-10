const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({executablePath: '/usr/bin/chromium-browser'});
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

    // (1) click search button
    const searchSelector = '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button > span.DocSearch-Button-Container > span';
    await page.click(searchSelector);

    // (2) wait search box
    const typeSelector = '#docsearch-input';
    await page.waitForSelector(typeSelector);

    // (3) type into search box
    await page.type(typeSelector, 'andy popoo');

    // (4) wait for search result
    await new Promise(resolve => setTimeout(resolve, 500));
    const resultSelector = '#docsearch-hits1-item-4 > a';
    await page.waitForSelector(resultSelector);

    // (5) click the result
    await page.click(resultSelector);

    // (6) get the title
    const titleSelector = '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1';
    const textSelector = await page.waitForSelector(titleSelector);
    const fullTitle = await textSelector?.evaluate(el => el.innerText);

    // (7) print the title
    console.log(fullTitle);

    // Close the browser
    await browser.close();
})();