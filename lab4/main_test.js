const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  await page.goto('https://pptr.dev/', { waitUntil: 'networkidle0' });

  // 點搜尋按鈕
  await page.waitForSelector('.DocSearch-Button');
  await page.click('.DocSearch-Button');

  // 輸入關鍵字
  await page.waitForSelector('.DocSearch-Input');
  await page.type('.DocSearch-Input', 'andy popoo');

  // 等搜尋結果載入
  await page.waitForSelector('.DocSearch-Hit', { timeout: 15000 });
  await new Promise(resolve => setTimeout(resolve, 1000));

  // 找出第一筆 title 含 "ElementHandle." 的結果
  const targetHref = await page.$$eval('.DocSearch-Hit', hits => {
    const debugInfo = [];

    for (const hit of hits) {
      const title = hit.querySelector('.DocSearch-Hit-title')?.innerText.trim();
      debugInfo.push(title);
      if (title && title.includes('ElementHandle.')) {
        const aTag = hit.querySelector('a');
        return { href: aTag?.href || null, debugInfo };
      }
    }

    return { href: null, debugInfo };
  });


  // 前往連結，印出標題
  if (targetHref.href) {
    await page.goto(targetHref.href, { waitUntil: 'domcontentloaded' });
    const fullTitle = await page.title();
    const trimmed = fullTitle.split(' | ')[0];
    console.log(trimmed);
  } else {
    console.log('ElementHandle result not found.');
  }

  await browser.close();
})();
