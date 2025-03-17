const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

test('MailSystem.write should log then return correct message', (ctx) => {
    const mailSystem = new MailSystem();
    ctx.mock.method(console, 'log');

    const message = mailSystem.write('Alice');
    assert.strictEqual(console.log.mock.callCount(), 1);
    assert.strictEqual(message, 'Congrats, Alice!');

    console.log.mock.restore();
});

test('MailSystem.send should log then return boolean', (ctx) => {
    const mailSystem = new MailSystem();
    ctx.mock.method(console, 'log');

    ctx.mock.method(Math, 'random', () => 0.6);
    const success = mailSystem.send('Alice', 'context');
    assert.strictEqual(console.log.mock.callCount(), 2);
    assert.strictEqual(success, true);
    console.log.mock.resetCalls();

    ctx.mock.method(Math, 'random', () => 0.4);
    const fail = mailSystem.send('Alice', 'context');
    assert.strictEqual(console.log.mock.callCount(), 2);
    assert.strictEqual(fail, false);

    Math.random.mock.restore();
    console.log.mock.restore();
});

test('Application.getNames should read file successfully', async () => {
    fs.writeFileSync('name_list.txt', 'Alice\nBob');
    const app = new Application();

    const [people, selected] = await app.getNames();
    assert.deepStrictEqual(people, app.people);
    assert.deepStrictEqual(selected, app.selected);

    fs.unlinkSync('name_list.txt');
});

test('Application.getRandomPerson should return a valid person', async () => {
    fs.writeFileSync('name_list.txt', 'Alice\nBob');
    const app = new Application();
    // In constructor, usage of then() can't ensure getNames() is finished, so manually call with await.
    await app.getNames();

    const person = app.getRandomPerson();
    assert.ok(['Alice', 'Bob'].includes(person));

    fs.unlinkSync('name_list.txt');
});

test('Application.selectNextPerson should select a person who was not selected before', async (ctx) => {
    ctx.mock.method(console, 'log');
    fs.writeFileSync('name_list.txt', 'Alice\nBob');
    const app = new Application();
    await app.getNames();

    const mockFunc = ctx.mock.fn(() => 0.6);

    mockFunc.mock.mockImplementationOnce(() => 0);
    ctx.mock.method(Math, 'random', mockFunc);
    const firstSelection = app.selectNextPerson();
    assert.strictEqual(console.log.mock.callCount(), 1);
    assert.strictEqual(firstSelection, 'Alice');
    console.log.mock.resetCalls();

    mockFunc.mock.mockImplementationOnce(() => 0);
    ctx.mock.method(Math, 'random', mockFunc);
    const secondSelection = app.selectNextPerson();
    assert.strictEqual(console.log.mock.callCount(), 1);
    assert.strictEqual(secondSelection, 'Bob');
    console.log.mock.resetCalls();

    const fourthSelection = app.selectNextPerson();
    assert.strictEqual(console.log.mock.callCount(), 2);
    // Every person is selected, should return null.
    assert.strictEqual(fourthSelection, null);

    console.log.mock.restore();
    Math.random.mock.restore();
    fs.unlinkSync('name_list.txt');
});

test('Application.notifySelected should send emails correctly', async (ctx) => {
    ctx.mock.method(console, 'log');
    fs.writeFileSync('name_list.txt', 'Alice\nBob');
    const app = new Application();
    await app.getNames();

    const mockFunc = ctx.mock.fn(() => 'Bob');
    mockFunc.mock.mockImplementationOnce(() => 'Alice');
    ctx.mock.method(app, 'getRandomPerson', mockFunc);
    app.selectNextPerson();
    app.selectNextPerson();
    console.log(app.selected);

    console.log.mock.resetCalls();
    ctx.mock.method(app.mailSystem, 'write');
    ctx.mock.method(app.mailSystem, 'send');
    app.notifySelected();

    assert.strictEqual(console.log.mock.callCount(), 7);
    assert.strictEqual(app.mailSystem.write.mock.callCount(), 2);
    assert.strictEqual(app.mailSystem.send.mock.callCount(), 2);

    console.log.mock.restore();
    Math.random.mock.restore();
    fs.unlinkSync('name_list.txt');
});