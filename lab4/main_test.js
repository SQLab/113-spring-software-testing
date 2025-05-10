const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    const selectSearchButton = '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button';
    await page.waitForSelector(selectSearchButton);
    await page.click(selectSearchButton);
    // Type into search box
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input', 'andy popoo');
    // Wait for search result
    const searchResultSelect = '#docsearch-hits1-item-4 > a';
    // Get the `Docs` result section
    await page.waitForSelector(searchResultSelect);
    // Click on first result in `Docs` section
    await page.click(searchResultSelect)
    // Locate the title
    const textSelector = await page.waitForSelector(
        '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1'
    );
    const fullTitle = await textSelector?.evaluate(el => el.textContent);
    // // Print the title
    console.log(fullTitle);
    // // Close the browser
    await browser.close();
})();