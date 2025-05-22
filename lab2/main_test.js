const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

// 模擬 fs.readFile
function mockReadFile(path, encoding, callback) {
    callback(null, 'Alice\nBob\nCharlie'); // Stub
}
const mockFsRead = test.mock.method(fs, 'readFile', mockReadFile);

const { Application, MailSystem } = require('./main');

test('MailSystem: write()', () => {
    const mailSystem = new MailSystem;
    assert.strictEqual(mailSystem.write('Alice'), 'Congrats, Alice!');
});

test('MailSystem: send() success case', () => {
    function returnHigh() { return 0.9; } // Stub
    const mailSystem = new MailSystem();
    const mockRandom = test.mock.method(Math, 'random', returnHigh);
    assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), true);
    mockRandom.mock.restore();
});

test('MailSystem: send() failure case', () => {
    function returnLow() { return 0.1; } // Stub
    const mailSystem = new MailSystem();
    const mockRandom = test.mock.method(Math, 'random', returnLow);
    assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), false);
    mockRandom.mock.restore();
});

test('Application: constructor initializes names', async () => {
    const app = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10)); // Wait for async init
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
});

test('Application: getRandomPerson()', () => {
    function returnFirst() { return 0; }
    const app = new Application();
    const mockRandom = test.mock.method(Math, 'random', returnFirst);
    assert.strictEqual(app.getRandomPerson(), 'Alice');
    mockRandom.mock.restore();
});

test('Application: selectNextPerson()', async () => {
    const application = new Application();
    await new Promise(resolve => setTimeout(resolve, 50));

    function returnApple() {
        return 'Apple';
    }
    const mockrandompersonA = test.mock.method(application, 'getRandomPerson', returnApple);
    assert.strictEqual(application.selectNextPerson(), 'Apple');
    assert.deepStrictEqual(application.selected, ['Apple']);
    mockrandompersonA.mock.restore();
    
    let cnt = 0;
    function returnAppleThenBanana() {
        return cnt++ === 0 ? 'Apple' : 'Banana';
    }
    const mockrandompersonAB = test.mock.method(application, 'getRandomPerson', returnAppleThenBanana);
    assert.strictEqual(application.selectNextPerson(), 'Banana');
    assert.deepStrictEqual(application.selected, ['Apple', 'Banana']);
    mockrandompersonAB.mock.restore();

    function returnOrange() {
        return 'Orange';
    }
    const mockrandompersonO = test.mock.method(application, 'getRandomPerson', returnOrange);
    assert.strictEqual(application.selectNextPerson(), 'Orange');
    assert.deepStrictEqual(application.selected, ['Apple', 'Banana', 'Orange']);
    mockrandompersonO.mock.restore();
    
    assert.strictEqual(application.selectNextPerson(), null);
});

test('Application: notifySelected()', () => {
    const app = new Application();
    app.selected = ['Alice', 'Bob'];
    
    const mockWrite = test.mock.method(app.mailSystem, 'write');
    const mockSend = test.mock.method(app.mailSystem, 'send');
    
    app.notifySelected();
    
    assert.strictEqual(mockWrite.mock.callCount(), 2);
    assert.strictEqual(mockSend.mock.callCount(), 2);
    mockWrite.mock.restore();
    mockSend.mock.restore();
});
const { Application, MailSystem } = require('./main');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

const { Application, MailSystem } = require('./main');
