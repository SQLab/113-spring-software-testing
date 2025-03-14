const fs = require('fs');
// create a fake readFile function to use
const originalFsReadFile = fs.readFile;
fs.readFile = (path, encoding, callback) => {
  callback(null, "Alice\nBob\nCharlie");
};
const { Application, MailSystem } = require('./main');
const test = require('node:test');
const assert = require('assert');

// check  getNames returns correct people and empty selected
test('Application.getNames returns correct people and empty selected', async (t) => {
  const app = new Application();
  const [people, selected] = await app.getNames();
  assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);
  assert.deepStrictEqual(selected, []);
});

test('Application.getRandomPerson returns a valid person when people is non-empty', (t) => {
  const app = new Application();
  app.people = ['Alice', 'Bob', 'Charlie'];
  const person = app.getRandomPerson();
  assert.ok(['Alice', 'Bob', 'Charlie'].includes(person));
});

test('Application.getRandomPerson returns undefined when people is empty', (t) => {
  const app = new Application();
  app.people = [];
  const person = app.getRandomPerson();
  assert.strictEqual(person, undefined);
});

test('Application.selectNextPerson selects a new person (manual stub)', (t) => {
  const app = new Application();
  app.people = ['Alice', 'Bob', 'Charlie'];
  app.selected = ['Alice'];
  const originalGetRandomPerson = app.getRandomPerson;
  app.getRandomPerson = () => 'Bob';
  const selectedPerson = app.selectNextPerson();
  assert.strictEqual(selectedPerson, 'Bob');
  assert.deepStrictEqual(app.selected, ['Alice', 'Bob']);
  app.getRandomPerson = originalGetRandomPerson;
});

test('Application.selectNextPerson returns null when all are selected (manual spy)', (t) => {
  const app = new Application();
  app.people = ['Alice', 'Bob'];
  app.selected = ['Alice', 'Bob'];
  const logs = [];
  const originalLog = console.log;
  console.log = (msg) => { logs.push(msg); };
  const result = app.selectNextPerson();
  assert.strictEqual(result, null);
  assert.ok(logs.some(msg => msg.includes('all selected')));
  console.log = originalLog;
});

test('Application.notifySelected calls MailSystem methods (manual mock)', (t) => {
  const app = new Application();
  app.selected = ['Alice', 'Bob'];
  const calls = [];
  const mockMailSystem = {
    write(name) {
      calls.push({ method: 'write', name });
      return 'Congrats, ' + name + '!';
    },
    send(name, context) {
      calls.push({ method: 'send', name, context });
      return true;
    }
  };
  app.mailSystem = mockMailSystem;
  app.notifySelected();
  assert.strictEqual(calls.length, 4);
  assert.deepStrictEqual(calls[0], { method: 'write', name: 'Alice' });
  assert.deepStrictEqual(calls[1], { method: 'send', name: 'Alice', context: 'Congrats, Alice!' });
  assert.deepStrictEqual(calls[2], { method: 'write', name: 'Bob' });
  assert.deepStrictEqual(calls[3], { method: 'send', name: 'Bob', context: 'Congrats, Bob!' });
});

test('MailSystem.write returns correct message and logs output', (t) => {
  const ms = new MailSystem();
  const logs = [];
  const originalLog = console.log;
  console.log = (msg) => { logs.push(msg); };
  const result = ms.write('Alice');
  assert.strictEqual(result, 'Congrats, Alice!');
  assert.ok(logs.some(msg => msg.includes('--write mail for Alice--')));
  console.log = originalLog;
});

test('MailSystem.send returns a boolean value and logs output', (t) => {
  const ms = new MailSystem();
  const logs = [];
  const originalLog = console.log;
  console.log = (msg) => { logs.push(msg); };
  const result = ms.send('Alice', 'Hello');
  assert.strictEqual(typeof result, 'boolean');
  assert.ok(logs.some(msg => msg.includes('--send mail to Alice--')));
  console.log = originalLog;
});
