const puppeteer = require('puppeteer')

;(async () => {
  // Launch the browser and open a new blank page
  const browser = await puppeteer.launch()
  const page = await browser.newPage()
  await page.setViewport({ width: 1920, height: 1080 })

  // Navigate the page to a URL
  await page.goto('https://pptr.dev/')

  // Hints:
  // Click search button
  const searchButtonSelector = '.DocSearch-Button'
  await page.locator(searchButtonSelector).click()

  // Type into search box
  const searchBoxSelector = '.DocSearch-Input'
  await page.waitForSelector(searchBoxSelector)
  await page.locator(searchBoxSelector).fill('andy popoo')

  // Wait for search result
  await new Promise((r) => setTimeout(r, 5000))

  // Get the `dragAndDrop()` result section
  const dragAndDropSelector = await page.waitForSelector('#docsearch-hits1-item-4 a')
  await dragAndDropSelector.click()

  // Locate the title
  const titleSelector = await page.waitForSelector('h1')
  const title = await titleSelector?.evaluate((element) => element.textContent)

  // Print the title
  console.log(title)

  // Close the browser
  await browser.close()
})()
