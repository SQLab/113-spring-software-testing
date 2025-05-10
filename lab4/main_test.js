const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');
    // sometimes fault but I don't know why. answer :selector should correct.
    // Hints:
    // Click search button
    await page.waitForSelector('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');
  
    await page.click('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');
    // Type into search box
    await page.waitForSelector('#docsearch-input');
  
    await page.type('#docsearch-input','andy popoo');
    // Wait for search result
    await page.waitForSelector('body > div:nth-child(1) > div > div > div > div');
    
    // Get the `Docs` result section
    await page.waitForSelector('#docsearch-hits1-item-4 > a > div');
    // Click on first result in `Docs` section
    await page.click('#docsearch-hits1-item-4 > a > div > div.DocSearch-Hit-content-wrapper > span');

    // Locate the title
    const textSelector = '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1';
    const fultitle = await page.$eval(textSelector, element => element.innerText);
    // Print the title
    console.log(fultitle);
    // Close the browser
    await browser.close();
})();