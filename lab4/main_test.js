const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    await page.goto('https://pptr.dev/');
    await page.setViewport({ width: 1080, height: 1024 });

    await page.click('.DocSearch-Button');
    await page.waitForSelector('#docsearch-input');
    await page.type('#docsearch-input', 'andy popoo');

    await page.waitForFunction(() => {
        const sections = document.querySelectorAll('.DocSearch-Hit-source');
        return Array.from(sections).some(el => el.textContent.trim() === 'ElementHandle');
    }, { timeout: 5000 });

    const linkToClick = await page.evaluate(() => {
        const sections = document.querySelectorAll('.DocSearch-Hits');
        for (const section of sections) {
            const sourceDiv = section.querySelector('.DocSearch-Hit-source');
            if (sourceDiv && sourceDiv.textContent.trim() === 'ElementHandle') {
                const firstLink = section.querySelector('ul > li a');
                if (firstLink) {
                    return firstLink.href;
                }
            }
        }
        return null;
    });

    if (linkToClick) {
        await page.goto(linkToClick);
        const h1Text = await page.$eval('h1', el => el.textContent.trim());
        console.log(h1Text);
    } else {
        console.log('No link found for ElementHandle section');
    }

    await browser.close();
})();
