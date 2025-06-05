const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    await page.click('.DocSearch.DocSearch-Button');
    await page.waitForSelector('#docsearch-input', { visible: true });

    await page.type('#docsearch-input', 'andy popoo', { delay: 100 });

    await page.waitForSelector('#docsearch-list', { visible: true, timeout: 20000 });

    await page.click('#docsearch-hits1-item-4 a');

    await page.waitForSelector('header h1', { visible: true, timeout: 30000 });

    const headerContent = await page.$eval('header h1', element => element.textContent);
    console.log(`${headerContent}`);

    await browser.close();
})();