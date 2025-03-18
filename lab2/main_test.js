const assert = require('assert');
const test = require('node:test');
const { Application, MailSystem } = require('./main');
const fs = require('fs');
const TEST_FILE = 'name_list.txt';

function createTestFile(content = 'Alice\nBob\nCharlie') {
    fs.writeFileSync(TEST_FILE, content);
}

function removeTestFile() {
    if (fs.existsSync(TEST_FILE)) {
        fs.unlinkSync(TEST_FILE);
    }
}


test('MailSystem.write() should return a formatted congratulatory message', () => {
    const mail = new MailSystem();
    const message = mail.write('Sam');
    assert.strictEqual(message, 'Congrats, Sam!');
});


test('MailSystem.send() random test', () => {
    const mail = new MailSystem();
    const originalRandom = Math.random;

    // true
    Math.random = () => 1;
    assert.strictEqual(mail.send('TestUser', 'Test Content'), true);

    // false
    Math.random = () => 0;
    assert.strictEqual(mail.send('TestUser', 'Test Content'), false);

    Math.random = originalRandom;
});

test('Application initializes with people from file', async () => {
    createTestFile();

    try {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 100)); // Wait for async data load

        assert(Array.isArray(app.people));
        assert.strictEqual(app.people.length, 3);
        assert.strictEqual(app.selected.length, 0);
    } finally {
        removeTestFile();
    }
});



test('Application.selectNextPerson() should return unique people and null when list empty', async () => {
    createTestFile();

    try {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 100));

        const person1 = app.selectNextPerson();
        assert.ok(app.people.includes(person1));
        assert.strictEqual(app.selected.length, 1);

        const person2 = app.selectNextPerson();
        assert.ok(app.people.includes(person2));
        assert.strictEqual(app.selected.length, 2);
        app.selectNextPerson();
        const person4 = app.selectNextPerson();
        assert.strictEqual(person4, null);
    } finally {
        removeTestFile();
    }
});

test('Application.notifySelected() should trigger mail sending for selected people', async () => {
    createTestFile('Alice\nBob');

    try {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 150));

        app.selectNextPerson();
        app.selectNextPerson();

        let writeCount = 0;
        let sendCount = 0;
        app.mailSystem.write = (name) => {
            writeCount++;
            return `Congrats, ${name}!`;
        };
        app.mailSystem.send = (name, context) => {
            sendCount++;
            return true;
        };

        app.notifySelected();

        assert.strictEqual(writeCount, 2);
        assert.strictEqual(sendCount, 2);
    } finally {
        removeTestFile();
    }
});

test('Application.notifySelected() should not send mails if no one is selected', () => {
    createTestFile('Alice\nBob');

    const app = new Application();
    app.selected = [];

    let writeCalls = 0;
    let sendCalls = 0;

    app.mailSystem.write = () => { writeCalls++; };
    app.mailSystem.send = () => { sendCalls++; };

    app.notifySelected();

    assert.strictEqual(writeCalls, 0);
    assert.strictEqual(sendCalls, 0);
    removeTestFile();

});

test('Application.selectNextPerson(), returns null if people is empty', () => {
    createTestFile('Alice\nBob');

    const app = new Application();
    app.people = [];
    app.selected = [];

    const person = app.selectNextPerson();
    assert.strictEqual(person, null);
    removeTestFile();

});
