const test = require('node:test');
const assert = require('assert');
// const { Application, MailSystem } = require('./main');

// 使用 Stub、Mock 和 Spy
const fs = require('fs');

// 模擬 fs.readFile 方法，回傳測試數據
const mockFileRead = test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'Mango\nApple\nBerry');  // 假設從檔案中讀取到這些名字
});

const { Application, MailSystem } = require('./main');

// 測試 MailSystem 的 write 函數
test("Check MailSystem write output with complex validation", () => {
    const mailSystem = new MailSystem();
    const recipient = 'Carrot';
    const expectedMessage = `Congrats, ${recipient}!`;  // 預期的訊息格式
    const actualMessage = mailSystem.write(recipient);  // 執行 write 函數來生成訊息
    
    // 驗證回傳結果是否為字串
    assert.strictEqual(typeof actualMessage, 'string', "Output should be a string");
    // 驗證訊息中是否包含接收者的名字
    assert.ok(actualMessage.includes(recipient), "Message should contain recipient name");
    // 驗證訊息是否與預期完全匹配
    assert.strictEqual(actualMessage, expectedMessage, "Generated message does not match expected");
});

// 測試 MailSystem 的 send 成功情況
test("Verify MailSystem send success", () => {
    const mailSystem = new MailSystem();
    const name = 'Carrot';
    // 模擬 Math.random() 返回 0.9，確保 send 成功
    const mockSuccess = test.mock.method(Math, 'random', () => 0.9); // > 0.5
    // 驗證 send 函數返回成功（true）
    assert.strictEqual(mailSystem.send(name, `Congrats, ${name}!`), true);
    // 恢復原始的 Math.random 方法
    mockSuccess.mock.restore();
});

// 測試 MailSystem 的 send 失敗情況
test("Verify MailSystem send failure", () => {
    const mailSystem = new MailSystem();
    const name = 'Carrot';
    // 模擬 Math.random() 返回 0.1，確保 send 失敗
    const mockFail = test.mock.method(Math, 'random', () => 0.1); // < 0.5
    // 驗證 send 函數返回失敗（false）
    assert.strictEqual(mailSystem.send(name, `Congrats, ${name}!`), false);
    // 恢復原始的 Math.random 方法
    mockFail.mock.restore();
});

// 測試 getRandomPerson 函數
test("Verify random selection in getRandomPerson", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));  // 模擬異步操作，等待 getNames 完成
    // 模擬 Math.random() 返回固定值 0.5
    const mockRand = test.mock.method(Math, 'random', () => 0.5);
    const selectedPerson = app.getRandomPerson();  // 執行隨機選擇人員的邏輯
    // 驗證隨機選擇的人員是否在 people 列表中
    assert.ok(app.people.includes(selectedPerson));
    // 恢復原始的 Math.random 方法
    mockRand.mock.restore();
});

// 測試 selectNextPerson 函數，確保每次選擇不同的人員
test("Validate next person selection", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));  // 模擬異步操作，等待 getNames 完成

    // 假設 getRandomPerson 返回固定值 'Apple'
    const originalGetRandomPerson = app.getRandomPerson;
    app.getRandomPerson = () => 'Apple';
    
    // 驗證選擇的第一個人是 'Apple'
    assert.strictEqual(app.selectNextPerson(), 'Apple');
    assert.deepStrictEqual(app.selected, ['Apple']);  // 驗證已選人員列表

    const personQueue = ['Apple', 'Berry', 'Mango'];
    // 模擬 getRandomPerson 返回不同的結果
    app.getRandomPerson = () => personQueue.shift();
    
    // 驗證選擇 'Berry'
    assert.strictEqual(app.selectNextPerson(), 'Berry');
    assert.deepStrictEqual(app.selected, ['Apple', 'Berry']);

    // 驗證選擇 'Mango'
    assert.strictEqual(app.selectNextPerson(), 'Mango');
    assert.deepStrictEqual(app.selected, ['Apple', 'Berry', 'Mango']);

    // 當所有人員都已選擇，應該返回 null
    assert.strictEqual(app.selectNextPerson(), null);

    // 恢復原始的 getRandomPerson 方法
    app.getRandomPerson = originalGetRandomPerson;
});

// 測試 notifySelected 是否正確觸發 mailSystem 的 write 和 send 函數
test("Ensure notifySelected correctly triggers mail functions", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));  // 模擬異步操作，等待 getNames 完成
    app.selected = ['Mango', 'Apple'];  // 模擬已選擇的人員
    
    const originalWrite = app.mailSystem.write;
    const originalSend = app.mailSystem.send;
    
    let writeCallCount = 0;
    let sendCallCount = 0;
    
    // 模擬 write 函數
    app.mailSystem.write = (name) => {
        writeCallCount++;
        return `Mocked message for ${name}`;  // 返回模擬訊息
    };
    
    // 模擬 send 函數
    app.mailSystem.send = () => {
        sendCallCount++;
        return true;  // 模擬發送成功
    };
    
    app.notifySelected();  // 執行通知已選擇人員

    // 驗證 write 和 send 被調用的次數與 selected 人數一致
    assert.strictEqual(writeCallCount, app.selected.length);
    assert.strictEqual(sendCallCount, app.selected.length);
    
    // 恢復原始的 write 和 send 方法
    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});