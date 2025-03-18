const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie');
});
const { Application, MailSystem } = require('./main');

test('MailSystem.write should return correct mail content', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const result = mailSystem.write(name);
    assert.strictEqual(result, `Congrats, Alice!`);

    const result2 = mailSystem.write('');
    assert.strictEqual(result2, 'Congrats, !');
});

test('MailSystem.send should return expected result', (t) => {
    const mailSystem = new MailSystem();
    const originalRandom = Math.random;

    Math.random = () => 0.75;
    const successResult = mailSystem.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(successResult, true);

    Math.random = () => 0.25;
    const failureResult = mailSystem.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(failureResult, false);

    Math.random = originalRandom;
});

test('Application.getRandomPerson should return a random person', async () => {
    const app = new Application();
    await app.getNames();
    
    const person = app.getRandomPerson();
    assert.ok(app.people.includes(person));
});

test('Application.selectNextPerson should return a person not selected before', async () => {
    const app = new Application();
    await app.getNames();
    
    const selected = [];
    for (let i = 0; i < app.people.length; i++) {
        const person = app.selectNextPerson();
        assert.ok(app.people.includes(person));
        assert.ok(!selected.includes(person));
        selected.push(person);
    }
    assert.strictEqual(app.selectNextPerson(), null);
});

test('Application.notifySelected should notify selected people', async () => {
    const app = new Application();
    await app.getNames();
    
    app.mailSystem.send = test.mock.fn(() => true, { times: app.people.length });
    for (let i = 0; i < app.people.length; i++) {
        app.selectNextPerson();
    }
    app.notifySelected();
    assert.strictEqual(app.mailSystem.send.mock.calls.length, app.people.length);
    for (const x of app.selected) {
        const call = app.mailSystem.send.mock.calls.find(call => call.arguments[0] === x);
        assert.ok(call);
    }
});