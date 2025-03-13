const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

const originalReadFile = fs.readFile;
fs.readFile = (filePath, encoding, callback) => {
    return callback(null, 'Alice\nBob\nCharlie');
};
const { Application, MailSystem } = require('./main');


// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

test("Test MailSystem's write", () => {
    const testMailSystem = new MailSystem();
    let logs = [];
    const originalLog = console.log;

    console.log = (message) => logs.push(message);
    assert.strictEqual(testMailSystem.write('HiHi'), 'Congrats, HiHi!');
    assert.ok(logs.includes("--write mail for HiHi--"));

    console.log = originalLog;
});

test("Test MailSystem's send", () => {
    const testMailSystem = new MailSystem();
    let logs = [];
    const originalLog = console.log;

    console.log = (message) => logs.push(message);

    const originalRandom = Math.random;
    Math.random = () => 0.6;

    const success = testMailSystem.send('HiHi', 'Congrats, HiHi!');
    assert.strictEqual(success, true);
    assert.ok(logs.includes('mail sent'));

    Math.random = () => 0.4;
    const fail = testMailSystem.send('HiHi', 'Congrats, HiHi!');
    assert.strictEqual(fail, false);
    assert.ok(logs.includes('mail failed'));

    Math.random = originalRandom;
    console.log = originalLog;
});

const util = require('util');
test("Test Application's getNames", async () => {
    const app = new Application();
    const [people, selected] = await app.getNames();

    assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(selected, []);
});

test("Test Application's contructor", async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));

    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
});


test("Test Application's getRandomPerson", async () => {
    const app = new Application();
    const [people, selected] = await app.getNames();
    app.people = people
    const person = app.getRandomPerson();
    
    assert.ok(people.includes(person));
});

test("Test Application's selectNextPerson", async () => {

    const app = new Application();
    const [people, selected] = await app.getNames();

    const chosenPeople = new Set();
    for (let i = 0; i < people.length; i++) {
        const person = app.selectNextPerson();

        assert.ok(person, "selectNextPerson() returned null too early!");
        assert.ok(people.includes(person), `Invalid person selected: ${person}`);
        assert.ok(!chosenPeople.has(person), `Duplicate person selected: ${person}`);
        chosenPeople.add(person);
    }

    const lastPerson = app.selectNextPerson();
    assert.strictEqual(lastPerson, null);

    app.people = ['Alice', 'Bob', 'Charlie'];
    app.selected = ['Alice'];
    let callCount = 0;
    app.getRandomPerson = () => {
      callCount++;
      return callCount === 1 ? 'Alice' : 'Bob';
    };

    const person = app.selectNextPerson();
  
    assert.strictEqual(person, 'Bob', "selectNextPerson should return 'Bob'");
    assert.deepStrictEqual(app.selected, ['Alice', 'Bob'], "selected should include 'Bob' after selection");
    assert.ok(callCount >= 2, "getRandomPerson should be called at least twice");

});



test("Test Application's notifySelected", async () => {
    
    const app = new Application();
    app.selected = ['Alice', 'Bob', 'Charlie']

    class FakeMailSystem {
        constructor() {
          this.writeCalls = [];
          this.sendCalls = [];
        }
        write(name) {
          this.writeCalls.push(name);
          return `Congrats, ${name}!`;
        }
        send(name, context) {
          this.sendCalls.push({ name, context });
          return true; 
        }
    }

    const fakeMailSystem = new FakeMailSystem();
    app.mailSystem = fakeMailSystem;
 
    app.notifySelected();
      
    assert.deepStrictEqual(fakeMailSystem.writeCalls, ['Alice', 'Bob', 'Charlie'], "write() should be called for each selected person");
      
    // Expect content
    const expectedSendCalls = [
    { name: 'Alice', context: 'Congrats, Alice!' },
    { name: 'Bob', context: 'Congrats, Bob!' },
    { name: 'Charlie', context: 'Congrats, Charlie!' }
    ];
    assert.deepStrictEqual(fakeMailSystem.sendCalls, expectedSendCalls, "send() should be called with the correct parameters for each selected person");
});

fs.readFile = originalReadFile