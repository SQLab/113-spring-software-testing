const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie');
});

const { Application, MailSystem } = require('./main');

test('Verify MailSystem write functionality', () => {
    const mailInstance = new MailSystem();
    assert.strictEqual(mailInstance.write('Alice'), `Congrats, Alice!`);
});

test('Check MailSystem send behavior', () => {
    const mailInstance = new MailSystem();
    test.mock.method(Math, 'random', () => 1);
    assert.strictEqual(mailInstance.send('Alice', 'success'), true);
    test.mock.method(Math, 'random', () => 0);
    assert.strictEqual(mailInstance.send('Alice', 'fail'), false);
});

test('Ensure Application initializes correctly', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    assert.deepStrictEqual(appInstance.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(appInstance.selected, []);
});

test('Test Application getRandomPerson method', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    test.mock.method(Math, 'random', () => 0);
    assert.strictEqual(appInstance.getRandomPerson(), appInstance.people[0]);
});

test('Validate Application selectNextPerson logic', async () => {
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

test('Confirm Application notifySelected behavior', async () => {
    const appInstance = new Application();
    await appInstance.getNames();
    appInstance.selected = ['Alice'];
    assert.strictEqual(appInstance.notifySelected(), undefined);
});