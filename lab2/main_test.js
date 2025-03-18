const test = require('node:test');
const assert = require('assert');
// Mocking fs.readFile
const fs = require('fs');
const ALL_PEOPLE = ['Alice', 'Bob', 'Charlie'];
test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    if (path === 'name_list.txt') {
        callback(null, ALL_PEOPLE.join('\n'));
    }
    callback(new Error('File not found'));
});
const { Application, MailSystem } = require('./main');

test("Check MailSystem write", async (t) => {
    const mailSystem = new MailSystem();
    const context = mailSystem.write('John Doe');
    assert.strictEqual(context, 'Congrats, John Doe!');
});

test("Check MailSystem send", async (t) => {
    const mailSystem = new MailSystem();
    const context = {};

    const originalRandom = Math.random;

    // Mocking Math.random to return value > 0.5
    Math.random = () => 0.6;
    assert.strictEqual(Math.random(), 0.6);

    const success = mailSystem.send('John Doe', context);
    assert.strictEqual(success, true);

    // Mocking Math.random to return value <= 0.5
    Math.random = () => 0.4;
    const failure = mailSystem.send('John Doe', context);
    assert.strictEqual(failure, false);
    Math.random = originalRandom;
}
);

test("Check Application getNames", async (t) => {
    const app = new Application();
    await app.getNames();
    assert.deepStrictEqual(app.people, ALL_PEOPLE);
    assert.deepStrictEqual(app.selected, []);
}
);

test("Check Application selectNextPerson", async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    const persons = [];
    for (let i = 0; i < ALL_PEOPLE.length + 1; i++) {
        const person = app.selectNextPerson();
        persons.push(person);
    }
    assert.strictEqual(app.selected.length, ALL_PEOPLE.length);
    assert.strictEqual(app.selectNextPerson(), null);
}
);

test("Check Application notifySelected", async (t) => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 100));
    const selected = app.selected;
    assert.strictEqual(selected.length, 0);
    for (let i = 0; i < ALL_PEOPLE.length; i++) {
        const person = app.selectNextPerson();
        assert.notStrictEqual(person, null);
        assert.ok(ALL_PEOPLE.includes(person));
        assert.strictEqual(app.selected.includes(person), true);
    }
    await app.notifySelected();
}
);
