const test = require('node:test');
const assert = require('assert');

// this section should be placed here
const fs = require('fs');
test.mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'Alice\nBob\nCharlie');
});

const { Application, MailSystem } = require('./main');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

// test MailSystem write method
test('MailSystem write method', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const context = mailSystem.write(name);

    assert.strictEqual(context, 'Congrats, Alice!');
});

// test MailSystem send method
test('MailSystem send method', () => {
    const mailSystem = new MailSystem();

    const name = 'Alice';
    const context = 'Congrats, Alice!';

    // success case
    test.mock.method(Math, 'random', () => 0.6);
    const success = mailSystem.send(name, context);
    assert.strictEqual(success, true);

    // failure case
    test.mock.method(Math, 'random', () => 0.4);
    const failure = mailSystem.send(name, context);
    assert.strictEqual(failure, false);
});


test('Application constructor', async () => {
    const application = new Application();
    await application.getNames();

    assert.deepStrictEqual(application.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(application.selected, []);
    assert.deepStrictEqual(typeof application.mailSystem, typeof new MailSystem());
});

test('Application getRandomPerson', async () => {
    const application = new Application();
    await application.getNames();
    
    // the first person
    test.mock.method(Math, 'random', () => 0.3);
    let randomPerson = application.getRandomPerson();
    assert.strictEqual(randomPerson, 'Alice');
    // the second person
    test.mock.method(Math, 'random', () => 0.6);
    randomPerson = application.getRandomPerson();
    assert.strictEqual(randomPerson, 'Bob');
    // the third person
    test.mock.method(Math, 'random', () => 0.9);
    randomPerson = application.getRandomPerson();
    assert.strictEqual(randomPerson, 'Charlie');
});

test('Application selectNextPerson', async () => {
    const application = new Application();
    await application.getNames();

    let person = 'Alice';
    test.mock.method(application, 'getRandomPerson', () => person);
    let nextPerson = application.selectNextPerson();
    assert.strictEqual(nextPerson, person);
    assert.strictEqual(application.selected.length, 1);

    test.mock.method(application, 'getRandomPerson', () => 'Bob');
    nextPerson = application.selectNextPerson();
    assert.strictEqual(nextPerson, 'Bob');
    assert.strictEqual(application.selected.length, 2);

    test.mock.method(application, 'getRandomPerson', () => 'Charlie');
    nextPerson = application.selectNextPerson();
    assert.strictEqual(nextPerson, 'Charlie');
    assert.strictEqual(application.selected.length, 3);

    test.mock.method(application, 'getRandomPerson', () => 'Alice');
    nextPerson = application.selectNextPerson();
    assert.strictEqual(nextPerson, null);
    assert.strictEqual(application.selected.length, 3);
});

test('Application notifySelected', async () => {
    const application = new Application();
    await application.getNames();
    
    const writeMock = test.mock.method(MailSystem.prototype, 'write', () => {
        return true;
    });
    const sendMock = test.mock.method(MailSystem.prototype, 'send', () => {
        return true;
    });
    application.notifySelected();
    assert.strictEqual(writeMock.mock.callCount(), 0);
    assert.strictEqual(sendMock.mock.callCount(), 0);

    application.selected = ['Alice', 'Bob', 'Charlie']
    application.notifySelected();
    assert.strictEqual(writeMock.mock.callCount(), application.selected.length);
    assert.strictEqual(sendMock.mock.callCount(), application.selected.length);
});