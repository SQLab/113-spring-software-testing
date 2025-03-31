const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({
        headless: 'new',
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto('https://pptr.dev/');

    await page.click('button.DocSearch-Button');

    await page.waitForSelector('input.DocSearch-Input');
    await page.click('input.DocSearch-Input');
    const keyword = 'andy popoo';
    await page.keyboard.type(keyword, { delay: 100 });

    await new Promise(resolve => setTimeout(resolve, 2000));

    const links = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('.DocSearch-Hit a')).map(a => a.textContent.trim());
    });

    const targetIndex = links.findIndex(text => text.includes('ElementHandle.dragAndDrop() method'));
    await page.evaluate((index) => {
        const allLinks = Array.from(document.querySelectorAll('.DocSearch-Hit a'));
        allLinks[index].click();
    }, targetIndex);

    await page.waitForSelector('h1');
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);

    await browser.close();
})();
