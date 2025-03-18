const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary
// Stub fs.readFile to return a mock name list
fs.readFile = (path, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie');
};
const { Application, MailSystem } = require('./main');

test('Application initializes people correctly', async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
});

test('Application selects a unique person each time', async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const person1 = app.selectNextPerson();
    const person2 = app.selectNextPerson();
    const person3 = app.selectNextPerson();
    const person4 = app.selectNextPerson();
    
    assert.strictEqual(new Set([person1, person2, person3]).size, 3);
    assert.strictEqual(person4, null);
});

test('Application getRandomPerson returns a person from the list', async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const randomPerson = app.getRandomPerson();
    assert(app.people.includes(randomPerson));
});

test('MailSystem write method formats correctly', (t) => {
    const mailSystem = new MailSystem();
    assert.strictEqual(mailSystem.write('Alice'), 'Congrats, Alice!');
});

test('MailSystem send method logs correct messages', (t) => {
    const mailSystem = new MailSystem();
    
    const originalLog = console.log;
    let logs = [];
    console.log = (msg) => logs.push(msg);
    
    Math.random = () => 0.9; // Force success
    const result = mailSystem.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(result, true);
    assert(logs.includes('--send mail to Alice--'));
    assert(logs.includes('mail sent'));
    
    console.log = originalLog;
});



test('Application notifySelected calls write and send correctly', async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    
    let writeCalls = 0;
    let sendCalls = 0;
    
    const originalWrite = app.mailSystem.write;
    app.mailSystem.write = (name) => {
        writeCalls++;
        return originalWrite(name);
    };
    
    const originalSend = app.mailSystem.send;
    app.mailSystem.send = (name, context) => {
        sendCalls++;
        return originalSend(name, context);
    };

    const originalRandom = Math.random;
    Math.random = () => 0.9;

    
    app.selectNextPerson();
    app.notifySelected();
    
    assert.strictEqual(writeCalls, 1);
    assert.strictEqual(sendCalls, 1);

    Math.random = () => 0.1;

    app.selectNextPerson();
    app.notifySelected();

    Math.random = originalRandom;
    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});
