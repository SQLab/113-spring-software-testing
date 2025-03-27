const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({ headless:  headless: process.env.CI === 'true' ? 'new' : false });
    const page = await browser.newPage();

    // Set viewport size
    await page.setViewport({ width: 1080, height: 1024 });

    // Navigate to the Puppeteer official website
    await page.goto('https://pptr.dev/');

    // Click the search button in the top-right navbar
    const searchBtnSelector =
        '#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button > span.DocSearch-Button-Container > svg';
    await page.waitForSelector(searchBtnSelector);
    await page.click(searchBtnSelector);

    // Type search query into the search input
    const searchInputSelector = '#docsearch-input';
    await page.waitForSelector(searchInputSelector);
    await page.type(searchInputSelector, 'andy popoo');

    // Wait for the specific search result item to appear
    const targetItemSelector = '#docsearch-hits1-item-4';
    await page.waitForSelector(targetItemSelector);

    // Wait until the <a> element inside the target result is rendered with content
    await page.waitForFunction(() => {
        const item = document.querySelector('#docsearch-hits1-item-4');
        const link = item?.querySelector('a');
        return !!link && link.textContent.trim().length > 0;
    });

    // Click the target result link from within the page context
    await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle0' }),
        page.evaluate(() => {
        const item = document.querySelector('#docsearch-hits1-item-4');
        const link = item?.querySelector('a');
        if (link) link.click();
        }),
    ]);

    // Wait for the title element to appear and extract its text content
    const titleSelector = '#__docusaurus_skipToContent_fallback h1';
    await page.waitForSelector(titleSelector);
    const titleHandle = await page.$(titleSelector);
    const fullTitle = titleHandle
        ? await page.evaluate(el => el.textContent, titleHandle)
        : null;

    // Print the page title after navigation
    console.log(fullTitle);

    // Close the browser
    await browser.close();
})();
