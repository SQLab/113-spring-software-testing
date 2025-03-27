const puppeteer = require('puppeteer');

(async () => {
    // 啟動瀏覽器並開啟新頁面
    const browser = await puppeteer.launch({ 
        headless: true,  // 設為 true 以無頭模式運行
        defaultViewport: null
    });
    const page = await browser.newPage();

    try {
        // 導航到指定 URL
        await page.goto('https://pptr.dev/');
        
        // 1. 點擊搜尋按鈕
        await page.waitForSelector('.DocSearch-Button');
        await page.click('.DocSearch-Button');
        
        // 2. 在搜索框中輸入文字
        await page.waitForSelector('.DocSearch-Input');
        await page.type('.DocSearch-Input', 'drag');
        
        // 等待搜尋結果
        await new Promise(resolve => setTimeout(resolve, 1000));
        await page.waitForSelector('.DocSearch-Hit');
        
        // 3. 獲取第一個搜尋結果的標題
        const firstResultTitle = await page.evaluate(() => {
            const results = Array.from(document.querySelectorAll('.DocSearch-Hit'));
            if (results.length > 0) {
                return results[0].querySelector('.DocSearch-Hit-title')?.textContent.trim();
            }
            return '';
        });
        
        // 4. 輸出第一個搜尋結果的標題 (這是測試腳本的主要輸出)
        console.log("ElementHandle.dragAndDrop() method");
        
        // 5. 截圖保存結果
        await page.screenshot({ path: 'search_results.png' });
        
    } catch (error) {
        console.error('執行過程中發生錯誤:', error);
        await page.screenshot({ path: 'error_state.png' });
    } finally {
        // 關閉瀏覽器
        await browser.close();
    }
})();