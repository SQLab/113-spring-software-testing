const test = require('node:test');
const assert = require('assert');

const fs = require('fs');

// Do before import Application
function returnData(path, encode, callback) {
    callback(null, 'Apple\nOrange\nBanana');    // stub
}
const mockreadfile = test.mock.method(fs, 'readFile', returnData);

const { Application, MailSystem } = require('./main');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

test("Test MailSystem write", () => {
    const mailSystem = new MailSystem;
    const name = 'Kiwi';
    const result = 'Congrats, ' + name + '!';
    assert.strictEqual(mailSystem.write(name), result);
});

test("Test MailSystem send(success)", () => {
    function returnOne() {
        return 1;
    }
    const mailSystem = new MailSystem;
    const name = 'Kiwi';
    const context = 'Congrats, ' + name + '!';
    const mockrandom1 = test.mock.method(Math, 'random', returnOne);    // stub
    assert.strictEqual(mailSystem.send(name, context), true);
    mockrandom1.mock.restore();
});

test("Test MailSystem send(failed)", () => {
    function returnZero() {
        return 0;
    }
    const mailSystem = new MailSystem;
    const name = 'Kiwi';
    const context = 'Congrats, ' + name + '!';
    const mockrandom0 = test.mock.method(Math, 'random', returnZero);
    assert.strictEqual(mailSystem.send(name, context), false);
    mockrandom0.mock.restore();
});

test("Test Application constructor", async () => {
    const application = new Application();
    await new Promise(resolve => setTimeout(resolve, 50));

    assert.deepStrictEqual(application.people, ['Apple', 'Orange', 'Banana']);
    assert.deepStrictEqual(application.selected, []);
});

test("Test Application getRandomPerson", async () => {
    const application = new Application();
    await new Promise(resolve => setTimeout(resolve, 50));

    function returnZero() {
        return 0;
    }
    const mockrandom0 = test.mock.method(Math, 'random', returnZero);
    assert.strictEqual(application.getRandomPerson(), 'Apple');
    mockrandom0.mock.restore();
});

test("Test Application selectNextPerson", async () => {
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

test("Test Application notifySelected", async () => {
    const application = new Application();
    await new Promise(resolve => setTimeout(resolve, 50));

    application.selected = ['Apple', 'Orange'];

    const mockwrite = test.mock.method(application.mailSystem, 'write');    // spy
    const mocksend = test.mock.method(application.mailSystem, 'send');      // spy
    application.notifySelected();
    assert.strictEqual(mockwrite.mock.callCount(), 2);
    assert.strictEqual(mocksend.mock.callCount(), 2);

    mockwrite.mock.restore();
    mocksend.mock.restore();
});
