const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    await page.goto('https://pptr.dev/');

    // Click search button using .DocSearch button
    await page.waitForSelector('.DocSearch-Button');
    await page.click('.DocSearch-Button');  // Using .DocSearch button selector

    // Type into search box using .DocSearch input
    await page.waitForSelector('.DocSearch-Input');
    await page.type('.DocSearch-Input', 'andy popoo');

    // Get the first result and click on it
    await page.waitForSelector('.DocSearch-Hit', { timeout: 20000 });
    await new Promise(resolve => setTimeout(resolve, 1000));

    const resultTitle = await page.$$eval('.DocSearch-Hit', hits => {
        for (const hit of hits) {
            const title = hit.querySelector('.DocSearch-Hit-title')?.innerText.trim();

            if (title && title.includes('ElementHandle.')) {
                return title; // Return the first matching title
            }
        }
        return null; // If no matching title found
    });

    if (resultTitle) {
        console.log(resultTitle); // Print the title of the first matching result
    } else {
        console.log('No title containing "ElementHandle." was found.');
    }

    // Close the browser
    await browser.close();
})();