const puppeteer = require('puppeteer');

(async () => {
    // 啟動瀏覽器
    const browser = await puppeteer.launch({ headless: false });
    // const browser = await puppeteer.launch({
    //     headless: 'new',
    //     args: ['--no-sandbox', '--disable-setuid-sandbox']
    // });
    const page = await browser.newPage();

    // 前往 Puppeteer 官方網站
    await page.goto('https://pptr.dev/', { waitUntil: 'domcontentloaded' });

    // 使用 setTimeout 替代 waitForTimeout，確保載入完整
    await new Promise(resolve => setTimeout(resolve, 2000));

    // 檢查搜尋按鈕的選擇器是否變更
    await page.waitForSelector('button.DocSearch-Button');
    await page.click('button.DocSearch-Button');

    // 等待搜尋框出現
    await page.waitForSelector('input.DocSearch-Input');

    // 輸入搜尋內容
    await page.type('input.DocSearch-Input', 'andy popoo', { delay: 100 });

    // 等待搜尋結果顯示
    await page.waitForSelector('.DocSearch-Hit');

    const dragAndDropSelector = await page.waitForSelector('#docsearch-hits1-item-4 a')
    await dragAndDropSelector.click()
    // 等待標題載入並抓取標題
    await page.waitForSelector('h1');
    const title = await page.$eval('h1', element => element.innerText);

    // 輸出標題
    console.log(`${title}`);
    // console.log('ElementHandle.dragAndDrop() method');
    // 關閉瀏覽器
    await browser.close();
})();
