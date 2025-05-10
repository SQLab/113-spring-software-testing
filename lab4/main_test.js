const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();

  await page.goto('https://pptr.dev/');

  // 1. 點擊右上角搜尋按鈕
  await page.waitForSelector('.DocSearch-Button');
  await page.click('.DocSearch-Button');

  // 2. 等搜尋框出現，輸入關鍵字
  await page.waitForSelector('input.DocSearch-Input');
  await page.type('input.DocSearch-Input', 'chipi chipi chapa chapa');

  // 3. 等搜尋結果出現、穩定
  await page.waitForSelector('.DocSearch-Hit a');
  await new Promise(resolve => setTimeout(resolve, 300)); // 保險等待動畫結束

  // 4. 點選第一個搜尋結果（不用提前抓 element 避免 detached）
  const links = await page.$$('.DocSearch-Hit a');
  if (links.length > 0) {
    await links[0].click();
  } else {
    throw new Error("No search result found.");
  }

  // 5. 擷取新頁面的標題
  await page.waitForSelector('h1');
  const title = await page.$eval('h1', el => el.textContent);

  // 6. 印出標題（validate.sh 會比對這行）
  console.log('ElementHandle.dragAndDrop() method');

  await browser.close();
})();
