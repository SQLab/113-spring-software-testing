const puppeteer = require('puppeteer');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  try {
    // 開啟 Puppeteer 官方網站並等待 DOM 完成載入
    await page.goto('https://pptr.dev/', { waitUntil: 'domcontentloaded' });

    // 停 2 秒以確保動畫/JS 載入完成
    await delay(1000);

    // 點擊右上角搜尋按鈕
    await page.waitForSelector('button.DocSearch.DocSearch-Button');
    await page.click('button.DocSearch.DocSearch-Button');

    // 等待搜尋輸入框出現，然後輸入查詢文字
    await page.waitForSelector('input.DocSearch-Input');
    await page.type('input.DocSearch-Input', 'Andy Popoo', { delay: 100 });

    // 等待搜尋結果出現，點選第四項（實際上是 ElementHandle.dragAndDrop() 的連結）
    await page.waitForSelector('.DocSearch-Hit');
    const target = await page.waitForSelector('#docsearch-hits1-item-4 a');
    await target.click();

    // 等待新頁面的標題出現
    const title = await page.$eval('h1', el => el.textContent);
    // Print 標題文字
    console.log(title);
  }catch (err) {
    console.error('[Error]', err);
  } finally {
    await browser.close();
  }
})();
