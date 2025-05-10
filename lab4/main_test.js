const puppeteer = require('puppeteer');

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Click search button
    await page.click("button.DocSearch");

    await sleep(1000);

    // Type chipi chipi chapa chapa in the search input
    await page.type("input.DocSearch-Input", "andy popoo");

    await sleep(1000);

    // click first element in the list
    await page.click("#docsearch-hits1-item-4 > a");

    // log title
    const title = await page.evaluate(() => {
        return document.querySelector("div.theme-doc-markdown > header > h1").innerText;
    });
    console.log(title);

    // Close the browser
    await browser.close();
})();
