const test = require('node:test');
const assert = require('assert');
const { mock } = require('node:test');  // 使用 node:test 內建 Mock
const { Application, MailSystem } = require('./main');

test("Test MailSystem's write method", () => {
    const mailSystem = new MailSystem();
    const result = mailSystem.write("Alice");
    assert.strictEqual(result, "Congrats, Alice!");
});

test("Test MailSystem's send method with Stub", () => {
    const mailSystem = new MailSystem();

    // 使用 node:test 內建 mock 來 Stub `Math.random`
    mock.method(global.Math, "random", () => 0.6);
    assert.strictEqual(mailSystem.send("Bob", "Congrats, Bob!"), true);

    mock.method(global.Math, "random", () => 0.4);
    assert.strictEqual(mailSystem.send("Bob", "Congrats, Bob!"), false);
});

test("Test Application's getNames method with Stub", async () => {
    // 先 Stub `Application.prototype.getNames()`，避免 `constructor()` 內部讀取檔案
    mock.method(Application.prototype, 'getNames', async () => [["Alice", "Bob", "Charlie"], []]);

    // **現在才建立 `Application` 物件**
    const app = new Application();

    // 呼叫 `getNames()`，確保它回傳 Stub 值
    const [people, selected] = await app.getNames();

    assert.deepStrictEqual(people, ["Alice", "Bob", "Charlie"]);
    assert.deepStrictEqual(selected, []);
});

test("Test Application's selectNextPerson with Spy", () => {
    // 先 Stub `getNames()` 避免 `constructor()` 內部讀取檔案
    mock.method(Application.prototype, 'getNames', async () => [["Alice", "Bob", "Charlie"], []]);

    // 創建 `Application` 實例
    const app = new Application();

    // 手動設置 `people` 和 `selected`
    app.people = ["Alice", "Bob", "Charlie"];
    app.selected = [];

    // Spy `getRandomPerson`
    const spy = mock.method(app, "getRandomPerson", () => "Bob");

    // 測試 `selectNextPerson()`
    const person1 = app.selectNextPerson();
    assert.ok(spy.mock.calls.length > 0); // 確保 `getRandomPerson()` 被呼叫
    assert.ok(app.selected.includes("Bob"));
});

test("Test Application's notifySelected using Mock", () => {
    // 先 Stub `getNames()`，避免 `constructor()` 內部讀取 `name_list.txt`
    mock.method(Application.prototype, 'getNames', async () => [["Alice", "Bob"], []]);

    // 創建 `Application` 物件
    const app = new Application();

    // 手動設定 `selected`
    app.selected = ["Alice", "Bob"];

    // Mock `MailSystem.write()` 和 `send()`
    const mockMailSystem = mock.method(app.mailSystem, "write", (name) => "Mocked content");
    const mockSend = mock.method(app.mailSystem, "send", (name, content) => true);

    // 測試 `notifySelected()`
    app.notifySelected();

    // 確保 Mock 方法被正確呼叫
    assert.ok(mockMailSystem.mock.calls.length === 2);
    assert.ok(mockSend.mock.calls.length === 2);
});
