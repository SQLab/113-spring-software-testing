const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    // const browser = await puppeteer.launch();
    const browser = await puppeteer.launch({
        headless: true, // 關閉無頭模式
        slowMo: 50, // 設定操作延遲，單位為毫秒
        args: ['--start-maximized'] // 啟動時最大化視窗
      });
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    const searchButtonSelector = '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button';
    await page.waitForSelector(searchButtonSelector);
    await page.click(searchButtonSelector);
    // Type into search box
    const searchBoxSelector = '#docsearch-input';
    await page.waitForSelector(searchBoxSelector);
    await page.type(searchBoxSelector, 'andy popoo');
    // Wait for search result
    const searchResultSelector = '#docsearch-hits1-item-4 > a > div';
    await page.waitForSelector(searchResultSelector, { visible: true });
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    await page.click(searchResultSelector);
    // Locate the title
    const textSelector = await page.waitForSelector(
        '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div > div > article > div.theme-doc-markdown.markdown > header > h1'
    );
    const fullTitle = await textSelector?.evaluate(el => el.textContent);
    // Print the title
    console.log(fullTitle);

    // Close the browser
    await browser.close();
})();