const puppeteer = require('puppeteer');

(async () => {
    
    // const browser = await puppeteer.launch({ headless: false });
    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();


    await page.goto('https://pptr.dev/', { waitUntil: 'domcontentloaded' });


    await new Promise(resolve => setTimeout(resolve, 2000));


    await page.waitForSelector('button.DocSearch-Button');
    await page.click('button.DocSearch-Button');

    await page.waitForSelector('input.DocSearch-Input');

    await page.type('input.DocSearch-Input', 'andy popoo', { delay: 1000 });

    
    await page.waitForSelector('.DocSearch-Hit');

    const dragAndDropSelector = await page.waitForSelector('#docsearch-hits1-item-4 a')
    await dragAndDropSelector.click()
    const titleSelector = await page.waitForSelector('h1')
    const title = await titleSelector?.evaluate((element) => element.textContent)
    
    console.log(title);
    // console.log('ElementHandle.dragAndDrop() method');
    await browser.close();
})();

