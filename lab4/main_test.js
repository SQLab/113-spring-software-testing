const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    // Type into search box
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title

    await page.click('.DocSearch-Button');
    const searchBoxSelector = '.DocSearch-Input';
    await page.waitForSelector(searchBoxSelector);
    await page.type(searchBoxSelector, 'andy popoo');

    await page.locator('#docsearch-hits1-item-4 > a:nth-child(1) > div:nth-child(1)').click();
    // await page.waitForSelector(`.theme-doc-markdown > header:nth-child(1) > h1:nth-child(1)').innerText`);
    await new Promise(r => setTimeout(r, 1000));
    title = await page.evaluate(`document.querySelector('.theme-doc-markdown > header:nth-child(1) > h1:nth-child(1)').innerText `);
    console.log(title);
    
    await page.screenshot({path: 'screenshot.png'});
    

    // Close the browser
    await browser.close();
})();
