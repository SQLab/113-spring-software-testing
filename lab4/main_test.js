const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Click search button
    await page.waitForSelector('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');
    await page.click('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');

    // Wait for search input and type
    await page.waitForSelector('#docsearch-input');
    await page.type('.DocSearch-Input', 'andy popoo');
    
    // Wait for search results
    await page.locator('#docsearch-hits1-item-4').click();

    const textSelector = await page.waitForSelector(
        'text=ElementHandle.dragAndDrop() method'
    );

    const fullTitle = await textSelector?.evaluate(el => el.textContent);
    
    // Click the first result in Docs section
    console.log(fullTitle);

    // Close the browser
    await browser.close();
})();