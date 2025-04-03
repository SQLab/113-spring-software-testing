const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.waitForSelector('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button > span.DocSearch-Button-Container > svg');
    await page.click('#__docusaurus > nav > div.navbar__inner > div.navbar__items.navbar__items--right > div.navbarSearchContainer_IP3a > button > span.DocSearch-Button-Container > svg');
    // Type into search box
    // await page.type('.navbarSearchContainer_IP3a input', 'chipi chipi chapa chapa');
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input', 'andy popoo' , { delay: 100 });

    // Wait for search result
    await page.waitForSelector('.DocSearch-Hit');
    // Get the `Docs` result section
    // Click on first result in `Docs` section
    await page.waitForSelector('.DocSearch-Hit', { timeout: 5000 });

    const docsSection = await page.$$('.DocSearch-Hit');
    const limit = 5; // limit the number of results to show
    const visibleDocsSection = docsSection.slice(0, limit);  // get the first 5 results
    if (visibleDocsSection.length > 0) {
        for (let i = 0; i < visibleDocsSection.length; i++) {
            const title = await visibleDocsSection[i].$eval('.DocSearch-Hit-title', el => el.innerText);
            // console.log(`搜尋結果 ${i + 1}: ${title}`);
        }
        
        // Click the first result
        const clickedTitle = await visibleDocsSection[0].$eval('.DocSearch-Hit-title', el => el.innerText);
        // console.log(`即將點擊的搜尋結果: ${clickedTitle}`);
        
        await visibleDocsSection[4].click();
    } else {
        console.log('Results not found!');
    }
    // if (visibleDocsSection.length > 0) {
    //     await visibleDocsSection[0].click();  // 點擊第一個搜尋結果
    // } else {
    //     console.log('搜尋結果沒有找到！');
    // }
    // Locate the title
    // Print the title
    await page.waitForSelector('h1');
    const title = await page.$eval('h1', element => element.innerText);
    console.log(title);
    // Close the browser
    await browser.close();
})();