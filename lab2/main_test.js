const assert = require('assert');
const test = require('node:test');
const { Application, MailSystem } = require('./main');
const fs = require('node:fs');
const util = require('util');
const writeFile = util.promisify(fs.writeFile);
const unlinkFile = util.promisify(fs.unlink);

async function createTestFile(content = "Alice\nBob\nCharlie") {
  await writeFile("name_list.txt", content, 'utf-8');
}

async function removeTestFile() {
  try {
    await unlinkFile("name_list.txt");
  } catch (error) {
    // Ignore errors 
  }
}

// 我們使用單獨的測試進行設置
test('Setup test environment', async () => {
  await createTestFile();
});

// Tests for MailSystem class
test('MailSystem.write should return congratulatory message', (t) => {
  const mailSystem = new MailSystem();
  const result = mailSystem.write('John');
  assert.strictEqual(result, 'Congrats, John!');
});

test('MailSystem.send should return boolean indicating success', (t) => {
  const mailSystem = new MailSystem();

  const originalRandom = Math.random;

  // Test success case
  Math.random = () => 0.6; // return true 
  const successResult = mailSystem.send('John', 'Congrats, John!');
  assert.strictEqual(successResult, true);

  // Test failure case
  Math.random = () => 0.4; // return false
  const failureResult = mailSystem.send('John', 'Congrats, John!');
  assert.strictEqual(failureResult, false);

  Math.random = originalRandom;
});

test('Application constructor should initialize properties', async (t) => {
  await createTestFile("Alice\nBob\nCharlie");
  const app = new Application();

  await new Promise(resolve => setTimeout(resolve, 10));

  assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
  assert.deepStrictEqual(app.selected, []);
  assert.ok(app.mailSystem instanceof MailSystem);
});

test('getNames should read and parse names from file', async (t) => {
  await createTestFile("Dave\nEve\nFrank");

  const app = new Application();
  const [people, selected] = await app.getNames();

  assert.deepStrictEqual(people, ['Dave', 'Eve', 'Frank']);
  assert.deepStrictEqual(selected, []);
});

test('getRandomPerson should return a person from the people array', async (t) => {
  const app = new Application();

  await new Promise(resolve => setTimeout(resolve, 10));

  app.people = ['Alice', 'Bob', 'Charlie'];

  const originalRandom = Math.random;
  const originalFloor = Math.floor;

  // Create a spy 
  let floorCallCount = 0;
  Math.floor = (num) => {
    floorCallCount++;
    return originalFloor(num);
  };

  Math.random = () => 0; //select idx 0 
  assert.strictEqual(app.getRandomPerson(), 'Alice');

  Math.random = () => 0.34; // select idx 1 
  assert.strictEqual(app.getRandomPerson(), 'Bob');

  Math.random = () => 0.67; // select idx 2 
  assert.strictEqual(app.getRandomPerson(), 'Charlie');

  assert.strictEqual(floorCallCount, 3);

  Math.random = originalRandom;
  Math.floor = originalFloor;
});

test('selectNextPerson should select a random unselected person', async (t) => {
  const app = new Application();
  await new Promise(resolve => setTimeout(resolve, 10));

  app.people = ['Alice', 'Bob', 'Charlie'];
  app.selected = [];

  const originalGetRandomPerson = app.getRandomPerson;
  let randomPersonCalls = 0;

  app.getRandomPerson = () => {
    randomPersonCalls++;
    if (randomPersonCalls === 1) return 'Bob';
    if (randomPersonCalls === 2) return 'Bob'; 
    if (randomPersonCalls === 3) return 'Alice'; 
    return 'Charlie';
  };

  const result = app.selectNextPerson();
  assert.strictEqual(result, 'Bob');
  assert.deepStrictEqual(app.selected, ['Bob']);

  const secondResult = app.selectNextPerson();
  assert.strictEqual(secondResult, 'Alice');
  assert.deepStrictEqual(app.selected, ['Bob', 'Alice']);

  app.getRandomPerson = originalGetRandomPerson;
});

test('selectNextPerson should return null when all people are selected', async (t) => {
  const app = new Application();  
  await new Promise(resolve => setTimeout(resolve, 10));

  app.people = ['Alice', 'Bob'];
  app.selected = ['Alice', 'Bob'];

  const result = app.selectNextPerson();

  assert.strictEqual(result, null);
});

test('notifySelected should send mail to all selected people', async (t) => {
  const app = new Application();  
  await new Promise(resolve => setTimeout(resolve, 10));

  app.selected = ['Alice', 'Bob'];

  const originalWrite = app.mailSystem.write;
  const originalSend = app.mailSystem.send;

  const writeCalls = [];
  const sendCalls = [];

  app.mailSystem.write = (name) => {
    writeCalls.push(name);
    return `Congrats, ${name}!`;
  };

  app.mailSystem.send = (name, context) => {
    sendCalls.push({ name, context });
    return true;
  };

  app.notifySelected();

  assert.strictEqual(writeCalls.length, 2);
  assert.strictEqual(sendCalls.length, 2);

  assert.strictEqual(writeCalls[0], 'Alice');
  assert.strictEqual(writeCalls[1], 'Bob');

  assert.strictEqual(sendCalls[0].name, 'Alice');
  assert.strictEqual(sendCalls[0].context, 'Congrats, Alice!');
  assert.strictEqual(sendCalls[1].name, 'Bob');
  assert.strictEqual(sendCalls[1].context, 'Congrats, Bob!');

  app.mailSystem.write = originalWrite;
  app.mailSystem.send = originalSend;
});

// 我們使用單獨的測試進行清理
test('Cleanup test environment', async () => {
  await removeTestFile();
});
