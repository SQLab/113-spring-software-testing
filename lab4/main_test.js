const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');
    // set viewport size
    await page.setViewport({ width: 1080, height: 1024 });
    // Hints:
    // Click search button
    // 點擊搜尋按鈕
    await page.click('.DocSearch-Button');
    // 等待搜尋框出現
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input', 'andy popoo');
    // 等待搜尋結果出現
    await page.waitForSelector("#docsearch-hits1-item-4 > a > div", { visible: true });
    // 點擊搜尋結果
    await page.click("#docsearch-hits1-item-4 > a > div");
    // 等待新頁面載入並定位標題（例如 h1 標籤）
    await page.waitForSelector('#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1');

    // 取得並印出標題文字
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);
     
    // Type into search box
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title

    // Close the browser
    await browser.close();
})();