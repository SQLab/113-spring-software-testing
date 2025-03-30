const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  // 前往 pptr.dev
  await page.goto('https://pptr.dev/', { waitUntil: 'networkidle0' });
  
  // 點擊搜尋按鈕
  await page.waitForSelector('button.DocSearch-Button');
  await page.click('button.DocSearch-Button');
  
  // 等待搜尋框出現並輸入關鍵字
  await page.waitForSelector('input.DocSearch-Input');
  await page.type('input.DocSearch-Input', 'andy popoo');
  
  // 等待搜尋結果載入
  await page.waitForSelector('.DocSearch-Hit', { timeout: 10000 });
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // 找出標題為 "ElementHandle.dragAndDrop() method" 的搜尋結果
  const targetHref = await page.$$eval('.DocSearch-Hit-title', titles => {
    for (const titleEl of titles) {
      if (titleEl.innerText.trim().includes('ElementHandle.dragAndDrop() method')) {
        const aTag = titleEl.closest('a');
        return aTag ? aTag.href : null;
      }
    }
    return null;
  });
  
  if (targetHref) {
    await page.goto(targetHref, { waitUntil: 'domcontentloaded' });
    const fullTitle = await page.title();
    // 如果有 " | Puppeteer" 就去除它
    const trimmedTitle = fullTitle.split(' | ')[0];
    console.log(trimmedTitle);
  } else {
    console.log('ElementHandle.dragAndDrop() method not found.');
  }
  
  await browser.close();
})();
