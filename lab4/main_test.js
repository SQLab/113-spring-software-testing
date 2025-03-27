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
    await page.type('#docsearch-input', 'andy popoo');
    
    // Wait for search results
    await page.waitForSelector('#docsearch-hits1-item-4 > a > div');
    // await page.waitForSelector('.DocSearch-Hit');
    
    // Click the first result in Docs section
    await page.waitForSelector('#docsearch-hits1-item-4 > a > div > div.DocSearch-Hit-content-wrapper > span');
    await page.click('#docsearch-hits1-item-4 > a > div > div.DocSearch-Hit-content-wrapper > span');
    
    // Wait for and get the titlex
    await page.waitForSelector('h1');
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);

    // Close the browser
    await browser.close();
})();