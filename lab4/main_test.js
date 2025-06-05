const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.locator('button.DocSearch.DocSearch-Button').click();
    // Type into search box
    await page.locator('input#docsearch-input.DocSearch-Input').fill('andy popoo');
    // Wait for search result
    // Get the `Docs` result section
    await page.locator('div.DocSearch-Dropdown div.DocSearch-Dropdown-Container section.DocSearch-Hits ul#docsearch-list li#docsearch-hits1-item-4.DocSearch-Hit').click();
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title
    const titleElement = await page.waitForSelector('header:nth-child(1) > h1:nth-child(1)');
    const titleText = await titleElement.evaluate(e => e.innerText);
    console.log(titleText);

    // Close the browser
    await browser.close();
})();