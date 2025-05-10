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
       
        const sections = document.querySelectorAll('.DocSearch-Hit-source');
        
        
        // 尋找包含ElementHandle的部分
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].textContent.includes('ElementHandle')) {
                
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
    

    // Wait for page to load
    await page.waitForSelector('h1');
    
    // Get the title text
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);
    // Hints:
    // Click search button
    // Type into search box
    // Wait for search result
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    // Locate the title
    // Print the title

    // Close the browser
    await browser.close();
})();
