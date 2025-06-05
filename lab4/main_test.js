const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({
    headless: true,      // ← 顯示瀏覽器畫面
    slowMo: 100           // ← 每步操作加 100ms 延遲，方便觀察
  });
  

  const page = await browser.newPage();
  await page.goto('https://pptr.dev/');
  await page.setViewport({ width: 1280, height: 800 });

  await page.waitForSelector('button.DocSearch-Button');
  await page.click('button.DocSearch-Button');

  await page.waitForSelector('input.DocSearch-Input');
  await page.type('input.DocSearch-Input', 'andy popoo');

  const sections = await page.$$('section.DocSearch-Hits');
  let clicked = false;

  for (const section of sections) {
    // 抓出分類名稱
    const label = await section.$('.DocSearch-Hit-source');
    const labelText = label
      ? await label.evaluate(el => el.textContent.trim())
      : '';
  
    // 如果是 Documentation 區塊
    if (labelText === 'ElementHandle') {
      const firstLink = await section.$('li.DocSearch-Hit a');
      if (firstLink) {
        await firstLink.click();
  
        // 給點時間等待跳轉或內容更新（因為可能是錨點 #）
        await new Promise(resolve => setTimeout(resolve, 1000));
  
        const title = await page.$eval('h1', el => el.textContent.trim());
        console.log(title);
        
  
        clicked = true;
        break;
      } else {
        console.warn("⚠️ Documentation 區有資料，但沒有可點擊連結");
      }
    }
  }
  await browser.close();  
})();
