const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

// 模擬檔案讀取
const mockFileRead = test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'Mango\nGrapes\nPeach');
});

const { Application, MailSystem } = require('./main');

// 測試 MailSystem 的 write 方法
test("Check MailSystem write output with complex validation", () => {
    const mailSystem = new MailSystem();
    const recipient = 'Berry';
    const expectedMessage = `Congrats, ${recipient}!`;
    const actualMessage = mailSystem.write(recipient);
    
    assert.strictEqual(typeof actualMessage, 'string', "Output should be a string");
    assert.ok(actualMessage.includes(recipient), "Message should contain recipient name");
    assert.strictEqual(actualMessage, expectedMessage, "Generated message does not match expected");
});


// 測試 MailSystem 的 send 成功
test("Verify MailSystem send success", () => {
    const mailSystem = new MailSystem();
    const name = 'Berry';
    const mockSuccess = test.mock.method(Math, 'random', () => 0.9); // > 0/5
    assert.strictEqual(mailSystem.send(name, `Congrats, ${name}!`), true);
    mockSuccess.mock.restore();
});

// 測試 MailSystem 的 send 失敗
test("Verify MailSystem send failure", () => {
    const mailSystem = new MailSystem();
    const name = 'Berry';
    const mockFail = test.mock.method(Math, 'random', () => 0.1); // < 0.5
    assert.strictEqual(mailSystem.send(name, `Congrats, ${name}!`), false);
    mockFail.mock.restore();
});

// 測試 MailSystem 的 write 方法
test("Check MailSystem write output with complex validation", () => {
    const mailSystem = new MailSystem();
    const recipient = 'Blueberry';
    const expectedMessage = `Congrats, ${recipient}!`;
    const actualMessage = mailSystem.write(recipient);
    
    assert.strictEqual(typeof actualMessage, 'string', "Output should be a string");
    assert.ok(actualMessage.includes(recipient), "Message should contain recipient name");
    assert.strictEqual(actualMessage, expectedMessage, "Generated message does not match expected");
});

// 測試隨機選擇人員
test("Verify random selection in getRandomPerson", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));
    const mockRand = test.mock.method(Math, 'random', () => 0.5);
    const selectedPerson = app.getRandomPerson();
    assert.ok(app.people.includes(selectedPerson));
    mockRand.mock.restore();
});

test("Validate next person selection", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));

    // 模擬第一次選擇
    const originalGetRandomPerson = app.getRandomPerson;
    app.getRandomPerson = () => 'Grapes';
    
    assert.strictEqual(app.selectNextPerson(), 'Grapes');
    assert.deepStrictEqual(app.selected, ['Grapes']);

    // 依序選擇不同的人
    const personQueue = ['Grapes', 'Peach', 'Mango'];
    app.getRandomPerson = () => personQueue.shift();
    
    assert.strictEqual(app.selectNextPerson(), 'Peach');
    assert.deepStrictEqual(app.selected, ['Grapes', 'Peach']);

    assert.strictEqual(app.selectNextPerson(), 'Mango');
    assert.deepStrictEqual(app.selected, ['Grapes', 'Peach', 'Mango']);

    // 當所有人都被選完時回傳 null
    assert.strictEqual(app.selectNextPerson(), null);
    
    app.getRandomPerson = originalGetRandomPerson;
});

// 測試已選擇人員的通知功能
test("Ensure notifySelected correctly triggers mail functions", async () => {
    const app = new Application();
    await new Promise(res => setTimeout(res, 10));
    app.selected = ['Mango', 'Grapes'];
    
    const originalWrite = app.mailSystem.write;
    const originalSend = app.mailSystem.send;
    
    let writeCallCount = 0;
    let sendCallCount = 0;
    
    app.mailSystem.write = (name) => {
        writeCallCount++;
        return `Mocked message for ${name}`;
    };
    
    app.mailSystem.send = () => {
        sendCallCount++;
        return true;
    };
    
    app.notifySelected();
    
    assert.strictEqual(writeCallCount, app.selected.length);
    assert.strictEqual(sendCallCount, app.selected.length);
    
    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});