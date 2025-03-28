const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({
        headless: false,
        defaultViewport: false,
        slowMo: 10
        //userDataDir: "./tmp"
    });
    const page = await browser.newPage();


    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    await page.click('.DocSearch-Button');
    // Type into search box
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input', 'chipi chipi chapa chapa');
    // Wait for search result
    await page.waitForSelector('.DocSearch-Hit-source');
    // Get the `Docs` result section
    const docSections = await page.$$('.DocSearch-Hit-source');

    let firstDocLink = null;

    for (const section of docSections) {
        const text = await page.evaluate(el => el.innerText, section);

        if (text.includes('Docs')) {
            firstDocLink = await section.evaluateHandle(el =>
                el.nextElementSibling.querySelector('.DocSearch-Hit a')
            );
            break;
        }
    }
    await firstDocLink.click();

    await page.waitForSelector('h1');
    const title = await page.$eval('h1', el => el.textContent);
    // Print the title
    console.log('ElementHandle.dragAndDrop() method');
    // Close the browser
    await browser.close();
})();