const puppeteer = require('puppeteer');

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.waitForSelector('button.DocSearch-Button', { visible: true });
    await page.click('button.DocSearch-Button');

    // Type into search box
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input', 'andy popoo');
    await sleep(300);
    // Wait for search results  
    await page.waitForSelector('#docsearch-hits1-item-4 > a > div', { visible: true });
    
    await page.click('#docsearch-hits1-item-4 > a > div');
    // Find the first result in the Docs section and click it
    await page.waitForSelector('h1');
    const title = await page.$eval('h1', el => el.textContent.trim());
    // Wait for navigation to finish and the title to appear
    
    
    console.log(title)
    // Close the browser
    await browser.close();
})();