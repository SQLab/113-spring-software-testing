const puppeteer = require('puppeteer');
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({ headless: false });
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');
    await new Promise(resolve => setTimeout(resolve, 1000)); // wait 5 seconds

    // Click search button
    await page.click('button.DocSearch');
    await page.waitForSelector('input.DocSearch-Input');

    // Type into search box
    await page.type('input.DocSearch-Input', 'andy popoo');    

    // Wait for search result
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Get the `ElementHandle` result section
    // Click on first result in `ElementHandle` section
    await page.click('#docsearch-hits1-item-4');

    // Locate the title
    // Print the title
    const title = await page.evaluate(() => {
        return document.querySelector("div.theme-doc-markdown > header > h1").innerText;
    });
    console.log(title);
    
    // Close the browser
    await browser.close();
})();

