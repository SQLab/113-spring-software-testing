const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.click('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');
    // Type into search box
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input','andy popoo');
    // Wait for search result
    // Get the `Docs` result section
    await page.locator('#docsearch-hits1-item-4 > a > div').click();
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title
    // await page.waitForSelector('body > script')
    const textSelector = await page.waitForSelector(
        'text=ElementHandle.dragAndDrop() method'
    );
    // const textSelector = await page.waitForSelector('#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1');
    const title = await textSelector?.evaluate(el => el.textContent);
    console.log(title);
    // Close the browser
    await browser.close();
})();