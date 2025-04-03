const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({
        headless: false,
        defaultViewport: {
            width: 1080,
            height: 1024
        },
        slowMo: 100
    });
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
    // await page.setViewport({width: 1080, height: 1024});    
    await page.click('button.DocSearch.DocSearch-Button');
    await page.waitForSelector('input.DocSearch-Input[type="search"]');
    await page.type('input.DocSearch-Input[type="search"]', 'chipi chipi chapa chapa');

    // 找到並點擊 Docs section 下的第一個結果
    await page.evaluate(() => {
        const sources = Array.from(document.querySelectorAll('.DocSearch-Hit-source'));
        const docsSource = sources.find(el => el.textContent.trim() === 'Docs');
        if (docsSource) {
            console.log('[debug]Find the Docs section');
            // 找到 Docs section 下的第一個結果並點擊
            const firstResult = docsSource.parentElement.querySelector('.DocSearch-Hit-Container');
            if (firstResult) {
                firstResult.click();
                console.log('[debug]Find the first result');
            }
        }
        else {
            console.log('[debug]No Docs section found');
        }
    });

    // 點擊 Docs section 下的第一個結果
    // await page.click('.DocSearch-Hit-Container');

    // 等待頁面導航完成
    // await page.waitForNavigation();

    // 獲取標題
    const title = await page.$eval('h2.anchor.anchorWithStickyNavbar_FNw8[id="puppeteer-features-fully-supported-over-webdriver-bidi"]', el => el.textContent);
    console.log(title);

    // wait for new page
    // const titleSelector = await page.waitForSelector('h2.anchor.anchorWithStickyNavbar_FNw8[id="puppeteer-features-fully-supported-over-webdriver-bidi"]');
    // console.log(titleSelector);
    // const title = await titleSelector?.evaluate(el => el.textContent);
    // const title = await page.$eval('h2.anchor.anchorWithStickyNavbar_FNw8', el => el.textContent);
    // console.log(title);

    // Close the browser
    await browser.close();
})();