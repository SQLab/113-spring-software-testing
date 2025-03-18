const test = require('node:test');
 const assert = require('assert');
 const fs = require('fs');

 test.mock.method(fs, 'readFile', (path, encoding, callback) => {
   callback(null, 'p1\np2\np3');
 });

 const { Application, MailSystem } = require('./main');

 test('MailSystem.write', (t) => {
   const mailSystem = new MailSystem();
   const result = mailSystem.write('person');
   assert.strictEqual(result, 'Congrats, person!');
 });

 test('MailSystem.send returns true when mail is sent', async (t) => {
  const mailSystem = new MailSystem();
  
  const originalRandom = Math.random;
  Math.random = () => 0.8;
  
  const success = mailSystem.send('person', 'some context');
  assert.strictEqual(success, true);
  
  Math.random = originalRandom;
});

test('MailSystem.send returns false when mail fails', async (t) => {
  const mailSystem = new MailSystem();
  
  const originalRandom = Math.random;
  Math.random = () => 0.3;
  
  const success = mailSystem.send('person', 'some context');
  assert.strictEqual(success, false);
  
  Math.random = originalRandom;
});

test('Application constructor initialization', async () => {
   const app = new Application();
   await new Promise(resolve => setImmediate(resolve));

   assert.deepStrictEqual(app.people, ['p1', 'p2', 'p3']);
   assert.deepStrictEqual(app.selected, []);
   assert(app.mailSystem instanceof MailSystem);
 });

test('test Application.getNames method', async () => {
  const app = new Application();
  const [people, selected] = await app.getNames();

  assert.deepStrictEqual(people, ['p1', 'p2', 'p3']);
  assert.deepStrictEqual(selected, []);
});

 test('Application.getRandomPerson',async (t) => {
   const app = new Application();
   await new Promise(resolve => setImmediate(resolve));

   const originalMath = Math.random;

   Math.random = () => 0.3;
   const result1 = app.getRandomPerson();
   assert.strictEqual(result1, 'p1');

   Math.random = () => 0.5;
   const result2 = app.getRandomPerson();
   assert.strictEqual(result2, 'p2');

   Math.random = () => 0.7;
   const result3 = app.getRandomPerson();
   assert.strictEqual(result3, 'p3');

   app.people = [];
   const result = app.getRandomPerson();
   assert.strictEqual(result, undefined);


   Math.random = originalMath;

 });


 test('selectNextPerson should select a new person each time and return null when all selected', async (t) => {
  const app = new Application();
  await new Promise(resolve => setImmediate(resolve));
  app.selected = [];

  // first call
  app.getRandomPerson = () => 'p2';
  const person1 = app.selectNextPerson();
  assert.ok(app.people.includes(person1), 'First person should be in the people array');
  assert.deepStrictEqual(app.selected, ['p2']);

  // second call
  app.getRandomPerson = () => 'p1';
  const person2 = app.selectNextPerson();
  assert.ok(app.people.includes(person2), 'Second person should be in the people array');
  assert.deepStrictEqual(app.selected, ['p2', 'p1']);

  // third call
  app.getRandomPerson = () => 'p3';
  const person3 = app.selectNextPerson();
  assert.ok(app.people.includes(person3), 'Third person should be in the people array');
  assert.deepStrictEqual(app.selected, ['p2' , 'p1', 'p3']);

  const selectedSet = new Set([person1, person2, person3]);
  assert.strictEqual(selectedSet.size, 3, 'Selected persons should be unique');
  assert.deepStrictEqual(app.selected, ['p2' , 'p1', 'p3']);

  const person4 = app.selectNextPerson();
  assert.strictEqual(person4, null, 'Should return null when all persons are selected');

  
});


 test('Application.selectNextPerson(already selected)', async(t) => {
   const app = new Application();
   await new Promise(resolve => setImmediate(resolve));
   app.selected = ['p2', 'p1'];

   const result = app.selectNextPerson();

   assert.strictEqual(result, 'p3');
   assert.deepStrictEqual(app.selected, ['p2', 'p1', 'p3']);
 });


 test('notifySelected calls write and send for each selected person', async (t) => {
    const app = new Application();
    await new Promise(resolve => setImmediate(resolve));
    
    app.selected = ['p2', 'p3'];

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

    assert.deepStrictEqual(writeCalls, ['p2', 'p3']);

    assert.deepStrictEqual(sendCalls, [
      { name: 'p2', context: 'Congrats, p2!' },
      { name: 'p3', context: 'Congrats, p3!' }
    ]);
  });
