const puppeteer = require('puppeteer');

(async () => {
  // Launch the browser (set headless: false if you want to see the actions)
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  // Navigate to the Puppeteer documentation site
  await page.goto('https://pptr.dev/');

  // Click the search button to reveal the search input
 
  await page.waitForSelector('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');
  await page.click('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button');



  // Type "andy popoo" into the search box with a slight delay between keystrokes
  await page.waitForSelector('#docsearch-input');
  await page.type('#docsearch-input', 'andy popoo');
  

  // Wait for search results to appear
  await page.waitForSelector('#docsearch-hits1-item-4 > a');
  await page.click('#docsearch-hits1-item-4 > a');


  await page.waitForSelector('#__docusaurus_skipToContent_fallback > div > div > main > div > div > div.col.docItemCol_nDJs > div > article > div.theme-doc-markdown.markdown > header > h1');
  const title = await page.$eval(
    '#__docusaurus_skipToContent_fallback > div > div > main > div > div > div.col.docItemCol_nDJs > div > article > div.theme-doc-markdown.markdown > header > h1',
    el => el.textContent.trim()
);
console.log(title);
await browser.close();
})();
