// main.test.js
const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

// -------------
// 1) mock fs.readFile
// -------------

test.mock.method(fs, 'readFile', (path, encoding, callback)=>
  {callback(null, 'Alice\nBob\nCharlie')});

// -------------
// 2) require main.js, get fixed fs.readFile
// -------------

const { Application, MailSystem } = require('./main');

// -------------
// 3) write test
// -------------

test('Test Application Constructor', async () => {
  const app = new Application();
  
  await app.getNames();
  
  assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
  assert.deepStrictEqual(app.selected, [], 'should be empty');
});

test('Test Application getRandomPerson', async () => {
  const app = new Application();

  await app.getNames();

  let i = 0;
  test.mock.method(Math, 'random', ()=>
    i
  );

  //[0*3]
  assert.deepStrictEqual(app.getRandomPerson(), app.people[0]);

  i = 0.34
  //[0.34*3] ~= [1]
  assert.deepStrictEqual(app.getRandomPerson(), app.people[1]);
});

test('Test Application selectNextPerson', async () => {
  const app = new Application();

  await app.getNames();

  let i = 0;

  test.mock.method(app, 'getRandomPerson', ()=>{
    return app.people[i++]
  });

  assert.deepStrictEqual(app.selectNextPerson(), app.people[0]); //i = 1
  i = 0; //ensure that find people start with first
  assert.deepStrictEqual(app.selectNextPerson(), app.people[1]); //i = 2
  app.selected = ['Alice', 'Bob', 'Charlie'];
  //now find people start with third, but already found.
  assert.deepStrictEqual(app.selectNextPerson(), null);
});

test('Test Application notifySelected', async () => {
  const app = new Application();

  await app.getNames();

  const writeCalls = [];
  const sendCalls = [];

  //be careful: due to notifySelected(), use app.mailSystem not new mail() !
  test.mock.method(app.mailSystem, 'write', (name)=>{
    writeCalls.push(name);
    return 'Congrats, ' + name + '!';
  });

  test.mock.method(app.mailSystem, 'send', (name, context)=>{
    sendCalls.push({name, context});
    return true; //for debug, all success!
  })

  app.selected = ['Alice', 'Bob'];

  app.notifySelected();

  assert.strictEqual(writeCalls.length, 2);
  assert.strictEqual(writeCalls[1], 'Bob');

  assert.strictEqual(sendCalls.length, 2);
  assert.strictEqual(sendCalls[0].name, 'Alice');
  assert.strictEqual(sendCalls[0].context, 'Congrats, Alice!');

  app.selected = [];
  writeCalls.length = 0;
  sendCalls.length = 0;

  app.notifySelected();
  assert.strictEqual(writeCalls.length, 0);
  assert.strictEqual(sendCalls.length, 0);
  
});

test('Test MailSystem write', async () => {
  const mail = new MailSystem();
  assert.deepStrictEqual(mail.write('Alice'), 'Congrats, ' + 'Alice' + '!');
});

test('Test MailSystem send', async () => {
  const mail = new MailSystem();

  let i = 0;
  test.mock.method(Math, 'random', ()=>
    i
  );

  assert.deepStrictEqual(mail.send('Alice', 'test failed'), false);
  i = 0.99;
  assert.deepStrictEqual(mail.send('Alice', 'test success'), true);
});
