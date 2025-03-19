const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

test('MailSystem.write returns correct message', async (t) => {
    const ms = new MailSystem();
    const name = 'Alice';
    const message = ms.write(name);
    assert.strictEqual(message, 'Congrats, ' + name + '!');
});

test('MailSystem.send returns true when Math.random() > 0.5', async (t) => {
    const ms = new MailSystem();
    const originalRandom = Math.random;
    Math.random = () => 0.6;
    const result = ms.send('Alice', 'Test context');
    assert.strictEqual(result, true);
    Math.random = originalRandom;
});

test('MailSystem.send returns false when Math.random() <= 0.5', async (t) => {
    const ms = new MailSystem();
    const originalRandom = Math.random;
    Math.random = () => 0.3;
    const result = ms.send('Alice', 'Test context');
    assert.strictEqual(result, false);
    Math.random = originalRandom;
});

test('Application getNames should correctly parse names and return an empty selected array', async () => {
    fs.writeFileSync('name_list.txt', 'Alice\nBob\nCharlie');
  
    const app = new Application();
    const [people, selected] = await app.getNames();
  
    assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(selected, []);
  
    fs.unlinkSync('name_list.txt');
});

test('Application.getRandomPerson returns undefined when people is empty', async (t) => {
    fs.writeFileSync('name_list.txt', 'Alice\nBob\nCharlie');
    const app = new Application();
    app.people = [];
    assert.strictEqual(app.getRandomPerson(), undefined);
});

test('Application.selectNextPerson works when most people are already selected', async (t) => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];
    app.selected = ['Alice', 'Bob'];
    const nextPerson = app.selectNextPerson();
    assert.strictEqual(nextPerson, 'Charlie');
    assert.strictEqual(app.selectNextPerson(), null);
});

test('Application.notifySelected calls write and send for each selected person', async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    app.selected = ['Alice', 'Bob'];
    const ms = app.mailSystem;
    const originalWrite = ms.write;
    const originalSend = ms.send;
    const writeCalls = [];
    const sendCalls = [];

    ms.write = (name) => { writeCalls.push(name); return 'Congrats, ' + name + '!'; };
    ms.send = (name, context) => { sendCalls.push(name); return true; };

    app.notifySelected();
    assert.deepStrictEqual(writeCalls.sort(), ['Alice', 'Bob']);
    assert.deepStrictEqual(sendCalls.sort(), ['Alice', 'Bob']);

    ms.write = originalWrite;
    ms.send = originalSend;
});
