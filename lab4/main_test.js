const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({
        headless: false,
        slowMo: 1
    });
    const page = await browser.newPage();
    // Navigate the page to a URL

    try {
        await page.goto('https://pptr.dev/');
        await page.setViewport({ width: 1080, height: 1024 });

        // Click search button
        await page.click('.DocSearch-Button');
        await page.waitForSelector('.DocSearch-Input');
        // Type into search box
        // Wait for search result
        await page.type('.DocSearch-Input', 'Andy popoo');

        // Get the `Docs` result section
        // Click on first result in `Docs` section
        await page.waitForFunction(() => {
            const bits = document.querySelectorAll('.DocSearch-Hit-source');
            return Array.from(bits).some(el => 
                el.textContent.trim() === 'ElementHandle'
            );
        }, { timeout: 8000 });

        await page.evaluate(() => {
            const bits = document.querySelectorAll('.DocSearch-Hit-source');
            for (const bite of bits) {
                if (bite.textContent.trim() === 'ElementHandle') {
                    const parent = bite.parentElement;
                    const first = parent.querySelector('.DocSearch-Hit a');
                    if (first) {
                        first.click();
                        return true;
                    }
                }
            }
            throw new Error('No results found for elementhandle');
        });

        // locate and print the title
        await page.waitForSelector('h1');
        const header = await page.$eval('h1', el => el.textContent.trim());
        console.log(header);

    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        await browser.close();
    }
})();