const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Click search button
    await page.click('.DocSearch');
    
    // Wait for search modal to appear
    await page.waitForSelector('.DocSearch-Modal');
    
    // Type into search box
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input', 'andy popoo');
    
    // Wait for search results to appear
    await page.waitForSelector('.DocSearch-Hit-source');
    
    // 增加等待時間，確保所有結果都完全加載
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // 使用page.evaluate直接在頁面上下文中找到ElementHandle部分並點擊第一個結果
    const clicked = await page.evaluate(() => {
        // 打印所有部分標題，用於診斷
        const sections = document.querySelectorAll('.DocSearch-Hit-source');
        
        console.log(`找到 ${sections.length} 個搜索部分`);
        
        for (let i = 0; i < sections.length; i++) {
            console.log(`部分 ${i+1}: "${sections[i].textContent}"`);
        }
        
        // 尋找包含ElementHandle的部分
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].textContent.includes('ElementHandle')) {
                console.log(`找到包含ElementHandle的部分: "${sections[i].textContent}"`);
                
                // 獲取這個部分的父元素
                const sectionParent = sections[i].parentElement;
                
                // 找到緊跟在這個部分後的第一個ul元素（這個ul包含搜索結果）
                let nextElement = sections[i].nextElementSibling;
                while (nextElement && nextElement.tagName !== 'UL') {
                    nextElement = nextElement.nextElementSibling;
                }
                
                if (nextElement && nextElement.tagName === 'UL') {
                    // 找到ul中的第一個li元素（第一個搜索結果）
                    const firstLi = nextElement.querySelector('li');
                    
                    if (firstLi) {
                        // 找到這個li中的a元素
                        const link = firstLi.querySelector('a');
                        
                        if (link) {
                            console.log(`找到連結: ${link.getAttribute('href')}`);
                            console.log(`連結文本: ${link.textContent}`);
                            
                            // 點擊這個連結
                            link.click();
                            return true;
                        }
                    }
                }
                
                break;
            }
        }
        
        return false;
    });
    
    if (!clicked) {
        console.log('無法在頁面上下文中找到並點擊ElementHandle部分的第一個結果');
    }
    
    // Wait for page to load
    await page.waitForSelector('h1');
    
    // Get the title text
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);

    // Close the browser
    await browser.close();
})();