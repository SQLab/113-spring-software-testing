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
    
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // 從頁面上下文中獲取信息並返回到Node.js
    await page.evaluate(() => {
        
        const sections = document.querySelectorAll('.DocSearch-Hit-source');
        
        // 尋找包含ElementHandle的部分
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].textContent.includes('ElementHandle')) {
              
                const sectionParent = sections[i].parentElement;
                
                
                let nextElement = sections[i].nextElementSibling;
                while (nextElement && nextElement.tagName !== 'UL') {
                    nextElement = nextElement.nextElementSibling;
                }
                
                if (nextElement && nextElement.tagName === 'UL') {
                    // （第一個搜索結果）
                    const firstLi = nextElement.querySelector('li');
                    
                    if (firstLi) {
                       
                        const link = firstLi.querySelector('a');
                        
                        if (link) {
                           
                            link.click();
                            return;
                        }
                    }
                }
                
                break;
            }
        }
    });
    
    // Wait for page to load
    await page.waitForSelector('h1');
    
    // Get the title text
    const title = await page.$eval('h1', el => el.textContent);
    console.log(title);

    // Close the browser
    await browser.close();
})();