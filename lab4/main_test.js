const puppeteer = require('puppeteer');


function wait(ms) {
    return new Promise(resolve =>setTimeout(() =>resolve(), ms));
};


(async () => {
    // Launch the browser and open a new blank page
    // const browser = await puppeteer.launch({ headless: false });
    const browser = await puppeteer.launch({});
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    const searchButtonText = '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button';
    await page.waitForSelector(searchButtonText);
    await page.click(searchButtonText);
    // Type into search box
    const searchInputText = '#docsearch-input';
    await page.waitForSelector(searchInputText);
    await page.type(searchInputText,'andy popoo');
    // Wait for search result
    // Get the `Docs` result section
    await page.locator('#docsearch-hits1-item-4 > a > div').click();
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title
    const textSelector = await page.waitForSelector(
        'text=ElementHandle.dragAndDrop() method'
    );
    const title = await textSelector?.evaluate(el => el.textContent);
    console.log(title);

    // Close the browser
    // await wait(3000);
    await browser.close();
})();