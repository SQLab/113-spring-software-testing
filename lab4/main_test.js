const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate the page to a URL
    await page.goto('https://pptr.dev/');

    // Hints:
    // Click search button
    const searchButton = 'button.DocSearch-Button';
    await page.waitForSelector(searchButton);
    await page.click(searchButton);
    
    
    // Type into search box
    const searchBox = 'input.DocSearch-Input'
    await page.waitForSelector(searchBox);
    await page.type(searchBox, 'andy popoo');

    // Wait for search result
    function delay(time) {
        return new Promise(function(resolve) { 
            setTimeout(resolve, time)
        });
    }
    await delay(4000);

    const docSearchHits = await page.$$('.DocSearch-Hits');
    for (let hit of docSearchHits) {
        const sourceElement = await hit.$('.DocSearch-Hit-source');
        if (sourceElement) {
            const textContent = await sourceElement.evaluate(el => el.textContent);

            // Get the `Docs` result section
            if (textContent && textContent.includes('ElementHandle')) {
                
                // Click on first result in `Docs` section
                const firstLink = await hit.$('a');
                if (firstLink) {
                    await firstLink.click();
                    break; 
                }
            }
        }
    }

    // Locate the title
    await page.waitForSelector('h1'); 
    const title = await page.$eval('h1', h1 => h1.innerText); 
  
    // Print the title
    console.log(title);
    
    // Close the browser
    await browser.close();
})();