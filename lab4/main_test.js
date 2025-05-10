const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  await page.goto('https://pptr.dev/');
  await page.setViewport({ width: 1080, height: 1024 });

  await page.click('button.DocSearch.DocSearch-Button');
  await page.waitForSelector('input#docsearch-input.DocSearch-Input');

  await page.type('input#docsearch-input.DocSearch-Input', 'andy popoo');

  await page.waitForSelector('.DocSearch-Hit');

  const links = await page.$$('.DocSearch-Hit a');

  for (const link of links) {
    const text = await link.evaluate(el => el.textContent.trim());
    if (text === 'ElementHandle.dragAndDrop() method') {
      const href = await link.evaluate(el => el.href);
      await page.goto(href); 
      break;
    }
  }

  const titleElement = await page.waitForSelector('h1');
  const fullTitle = await titleElement.evaluate(el => el.textContent.trim());
  console.log(fullTitle); 

  await browser.close();
})();
