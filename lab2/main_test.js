const { mock, test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

test.before(() => {
    fs.writeFileSync('name_list.txt', 'Alice\nBob\nCharlie');
});


test('MailSystem: write should return correct message', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const expected = `Congrats, ${name}!`;
    assert.strictEqual(mailSystem.write(name), expected);
});

test('MailSystem: send should return true when Math.random > 0.5', () => {
    const mailSystem = new MailSystem();
    const originalRandom = Math.random;
    Math.random = () => 0.9; // Mock Math.random to always return success

    assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), true);

    Math.random = originalRandom; 
});

test('MailSystem: send should return false when Math.random <= 0.5', () => {
    const mailSystem = new MailSystem();
    const originalRandom = Math.random;
    Math.random = () => 0.4; 

    assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), false);

    Math.random = originalRandom; 
});

test('Application: getNames should read from file and parse names', async () => {
    const app = new Application();
    await app.getNames();
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
});

test('Application: getRandomPerson should return a valid person', async () => {
    const app = new Application();
    await app.getNames();
    const person = app.getRandomPerson();
    assert.ok(['Alice', 'Bob', 'Charlie'].includes(person));
});

test('Application: selectNextPerson should select a new person', async () => {
    const app = new Application();
    await app.getNames();
    const person = app.selectNextPerson();
    assert.ok(app.selected.includes(person));
    assert.ok(app.people.includes(person));
});

test('Application: selectNextPerson should select a different person if one is already selected', async () => {
  const app = new Application();
  await app.getNames();
  app.selected = ['Alice'];
  const person = app.selectNextPerson();
  assert.ok(person);
  assert.ok(app.selected.includes(person));
  assert.notStrictEqual(person, 'Alice');
});

test('Application: selectNextPerson should return null when all are selected', async () => {
    const app = new Application();
    await app.getNames();
    app.selected = ['Alice', 'Bob', 'Charlie'];
    assert.strictEqual(app.selectNextPerson(), null);
});

test('Application: selectNextPerson should return the last person when only one person is left', async () => {
  const app = new Application();
  await app.getNames();
  app.selected = ['Alice', 'Bob'];
  const person = app.selectNextPerson();
  assert.strictEqual(person, 'Charlie');
});

test('Application: notifySelected should send mail to selected people', async () => {
    const app = new Application();
    await app.getNames();
    app.selected = ['Alice', 'Bob'];

    const mailSystem = new MailSystem();

    mailSystem.write = mock.fn((name) => {
        return 'Test Message'; 
    });

    mailSystem.send = mock.fn((name, context) => {
        return true; 
    });

    app.mailSystem = mailSystem;
    await app.notifySelected();

    assert.strictEqual(mailSystem.write.mock.callCount(), 2); 
    assert.strictEqual(mailSystem.send.mock.callCount(), 2); 
});
