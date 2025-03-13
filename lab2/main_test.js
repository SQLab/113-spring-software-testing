const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

test.mock.method(fs, 'readFile', (filePath, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie');
});

const { Application, MailSystem } = require('./main');

test('MailSystem - 測試 write 方法', () => {
    const mailer = new MailSystem();
    assert.strictEqual(mailer.write('Alice'), `Congrats, Alice!`);
});

test('MailSystem - 測試 send 方法', () => {
    const mailer = new MailSystem();
    
    test.mock.method(Math, 'random', () => 1);
    assert.strictEqual(mailer.send('Alice', 'success'), true);
    
    test.mock.method(Math, 'random', () => 0);
    assert.strictEqual(mailer.send('Alice', 'fail'), false);
});

test('Application - 測試建構函式', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    assert.deepStrictEqual(appInstance.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(appInstance.selected, []);
});

test('Application - 測試 getRandomPerson', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    
    test.mock.method(Math, 'random', () => 0);
    assert.strictEqual(appInstance.getRandomPerson(), appInstance.people[0]);
});

test('Application - 測試 selectNextPerson', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    let index = 0;
    
    test.mock.method(appInstance, 'getRandomPerson', () => appInstance.people[index++]);
    assert.strictEqual(appInstance.selectNextPerson(), appInstance.people[0]);
    index = 0;
    assert.strictEqual(appInstance.selectNextPerson(), appInstance.people[1]);
    
    appInstance.selected = [0, 0, 0];
    assert.strictEqual(appInstance.selectNextPerson(), null);
});

test('Application - 測試 notifySelected', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    appInstance.selected = ['Alice'];
    assert.strictEqual(appInstance.notifySelected(), undefined);
});
