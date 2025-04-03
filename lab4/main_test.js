const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    // 註解範圍為debug用途
    const browser = await puppeteer.launch({
        // headless: false,
        // defaultViewport: {
        //     width: 1080,
        //     height: 1024
        // },
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
    await page.type('input.DocSearch-Input[type="search"]', 'andy popoo');

    // 等待搜尋結果出現
    await page.waitForSelector('.DocSearch-Hit-source');
    await page.click('.DocSearch-Hit-source');
    // 找到並點擊包含特定文字的搜尋結果
    await page.evaluate(() => {
        const sources = Array.from(document.querySelectorAll('.DocSearch-Hit-source'));
        console.log('[debug]Found sources:', sources.length);
        
        const docsSource = sources.find(el => el.textContent.trim() === 'ElementHandle');
        console.log('[debug]Found Docs section:', docsSource ? 'yes' : 'no');
        
        if (docsSource) {
            // 找到 Docs section 下的第一個結果（不管內容是什麼）
            const firstHit = docsSource.parentElement.querySelector('.DocSearch-Hit');
            if (firstHit) {
                const link = firstHit.querySelector('a');
                if (link) {
                    const href = link.getAttribute('href');
                    const id = href.split('#')[1];
                    link.click();
                }
            }
        }
    });

    // 用正確的selector來取得title
    const titleSelector = await page.waitForSelector('div.theme-doc-markdown.markdown header h1');
    const title = await titleSelector?.evaluate(el => el.textContent);
    console.log(title);

    // Close the browser
    await browser.close();
})();