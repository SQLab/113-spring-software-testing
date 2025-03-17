const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const util = require('util');

// 明確 mock promisify(fs.readFile)
const originalPromisify = util.promisify;
util.promisify = (fn) => {
    if (fn === fs.readFile) {
        return () => Promise.resolve('Alice\nBob\nCharlie');
    }
    return originalPromisify(fn);
};

const { Application, MailSystem } = require('./main');

// MailSystem 測試
test('[unit] MailSystem.write should return correct mail content', () => {
    const mailSystem = new MailSystem();
    const result = mailSystem.write('Alice');
    assert.strictEqual(result, 'Congrats, Alice!');
});

test('[integration] MailSystem.send should log correct messages and return success', () => {
    const mailSystem = new MailSystem();
    const originalLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);

    const originalRandom = Math.random;
    Math.random = () => 0.8;

    const result = mailSystem.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(result, true);
    assert(logs.includes('--send mail to Alice--'));
    assert(logs.includes('mail sent'));

    console.log = originalLog;
    Math.random = originalRandom;
});

test('[unit] MailSystem.send should log failure when random returns low', () => {
    const mailSystem = new MailSystem();
    const originalLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);

    const originalRandom = Math.random;
    Math.random = () => 0.2;

    const result = mailSystem.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(result, false);
    assert(logs.includes('mail failed'));

    console.log = originalLog;
    Math.random = originalRandom;
});

// Application 測試
test('[integration] Application should initialize with names correctly', async () => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
});

test('[unit] Application.getRandomPerson should return a valid person', async () => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));
    const person = app.getRandomPerson();
    assert(['Alice', 'Bob', 'Charlie'].includes(person));
});

test('[integration] Application.selectNextPerson should select new person', async () => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));

    const selectedPerson = app.selectNextPerson();
    assert.strictEqual(app.selected.length, 1);
    assert(app.selected.includes(selectedPerson));
});

test('[integration] Application.selectNextPerson should return null if all selected', async () => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));

    app.selected = ['Alice', 'Bob', 'Charlie'];
    const person = app.selectNextPerson();
    assert.strictEqual(person, null);
});

test('[integration] Application.notifySelected should call MailSystem.write and send correctly', async () => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));

    app.selected = ['Alice', 'Bob'];
    let writeCount = 0, sendCount = 0;

    const originalWrite = app.mailSystem.write;
    const originalSend = app.mailSystem.send;

    app.mailSystem.write = (name) => { writeCount++; return `Congrats, ${name}!`; };
    app.mailSystem.send = (name, context) => { sendCount++; return true; };

    app.notifySelected();

    assert.strictEqual(writeCount, 2);
    assert.strictEqual(sendCount, 2);

    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});

// 測試完後復原
util.promisify = originalPromisify;
