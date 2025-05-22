const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.waitForSelector('.DocSearch-Button');
    await page.click('.DocSearch-Button');

    // Type into search box
    await page.locator('#docsearch-input').fill('andy popoo');

    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    await page.locator('#docsearch-hits1-item-4 > a > div').click();

    // Locate the title
    // Print the title
    await page.waitForSelector('h1');
    const title = await page.$eval('h1', (element) => element.textContent);

    // Print the title
    console.log(title);

    // Close the browser
    await browser.close();
})();