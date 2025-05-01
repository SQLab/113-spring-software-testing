const puppeteer = require('puppeteer');
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({ headless: false });
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    await page.click('button.DocSearch');
    await page.waitForSelector('input.DocSearch-Input');
    await page.type('input.DocSearch-Input', 'andy popoo');
    await new Promise(resolve => setTimeout(resolve, 1000)); 
    await page.waitForSelector('section.DocSearch-Hits');

    const sections = await page.$$('section.DocSearch-Hits');

    for (const section of sections) {
        const sourceDiv = await section.$('div.DocSearch-Hit-source');
        
        if (sourceDiv) {
            const text = await sourceDiv.evaluate(el => el.innerText.trim());
            if (text === 'ElementHandle') {
                // Click on the first result in this section
                const firstListItem = await section.$('#docsearch-list li');
                if (firstListItem) {
                    await firstListItem.click();
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    const title = await page.evaluate(() => {
                        return document.querySelector("div.theme-doc-markdown > header > h1").innerText;
                    });
                    console.log(title);
                } else {
                    console.log('No list item found in this section');
                }
            }
            
        } else {
            console.log('No ElementHandle found in this section');
        }
    }
    
    await browser.close();
})();

