import puppeteer from 'puppeteer';

async function runTest() {
    try {
        // Launch the browser
        const browser = await puppeteer.launch();
        
        // Create a new page
        const page = await browser.newPage();
        
        // Navigate to the Puppeteer documentation
        await page.goto('https://pptr.dev/');
        
        // Click search button
        await page.waitForSelector('.DocSearch-Button');
        await page.click('.DocSearch-Button');
        
        // Type into search box
        await page.waitForSelector('.DocSearch-Input');
        await page.type('.DocSearch-Input', 'andy popoo');
        
        // Wait for search results
        await page.waitForSelector('.DocSearch-Hit', { timeout: 20000 });
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Find the first result with "ElementHandle." in the title
        const resultTitle = await page.$$eval('.DocSearch-Hit', hits => {
            for (const hit of hits) {
                const title = hit.querySelector('.DocSearch-Hit-title')?.innerText.trim();
                
                if (title && title.includes('ElementHandle.')) {
                    return title;
                }
            }
            return null;
        });
        
        // Log the result
        if (resultTitle) {
            console.log(resultTitle);
        } else {
            console.log('No title containing "ElementHandle." was found.');
        }
        
        // Close the browser
        await browser.close();
    } catch (error) {
        console.error('An error occurred:', error);
    }
}

// Run the test
runTest();