const assert = require('assert');
const { Application, MailSystem } = require('./main');
const test = require('node:test');
const fs = require('fs');
const util = require('util');

const { hasUncaughtExceptionCaptureCallback } = require('process');


/*
Testing MailSystem class functions
*/
test('Testing function write', () => {
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const context = mailSystem.write(name);
    assert.strictEqual(context, 'Congrats, Alice!');
});

test('Testing function send when Math.random() > 0.5', () => {
    const originalRandom = Math.random;
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const context = 'Congrats, Alice!';
    Math.random = () => 0.6;
    const success = mailSystem.send(name, context);
    assert.strictEqual(success, true);
    Math.random = originalRandom;
});

test('Testing function send when Math.random() < 0.5', () => {
    const originalRandom = Math.random;
    Math.random = () => 0.4;
    const mailSystem = new MailSystem();
    const name = 'Alice';
    const context = 'Congrats, Alice!';
    const success = mailSystem.send(name, context);
    assert.strictEqual(success, false);
    Math.random = originalRandom;
});

/*
Testing Application class functions
*/

test('Application Constructor and async member function getNames', async () => {
    
    const fileContent = 'Alice\nBob\nCharlie\nDavid';

    fs.writeFileSync('name_list.txt', fileContent, 'utf8');

    const application = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10));

    assert.deepStrictEqual(application.people, ['Alice', 'Bob', 'Charlie', 'David']);
    assert.deepStrictEqual(application.selected, []);
    fs.unlinkSync('name_list.txt');

});

test('Testing getRandomPerson', async () => {
    //Stubbing getNames function
    const originalGetNames = Application.prototype.getNames;
    Application.prototype.getNames = async function() {
        return [['Alice', 'Bob', 'Charlie', 'David'], []];
    };
    
    const application = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10));

    const person = application.getRandomPerson();
    assert.ok(application.people.includes(person));
    Application.prototype.getNames = originalGetNames;
});

test('Testing selectNextPerson', async () => {
    //Stubbing getNames function
    const originalGetNames = Application.prototype.getNames;
    Application.prototype.getNames = async function() {
        return [['Alice', 'Bob', 'Charlie'], []];
    }
    const application = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10));

    const person1 = application.selectNextPerson();
    assert(application.people.includes(person1));
    assert(application.selected.includes(person1));


    const person2 = application.selectNextPerson();
    assert(application.people.includes(person2));
    assert(application.selected.includes(person2));
    assert.notStrictEqual(person1, person2);

    const person3 = application.selectNextPerson();
    assert(application.people.includes(person3));
    assert(application.selected.includes(person3)); 
    assert.notStrictEqual(person1, person3);
    assert.notStrictEqual(person2, person3);

    const result = application.selectNextPerson();
    assert.strictEqual(result, null);

    Application.prototype.getNames = originalGetNames;
});    

test('Testing selectNextPerson', async () => {
    //Stubbing getNames function
    const originalGetNames = Application.prototype.getNames;
    Application.prototype.getNames = async function() {
        return [['Alice', 'Bob'], []];
    }
    const application = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10));
    //Spying on console.log
    let logs = [];
    const originalLog = console.log;
    console.log = (message) => logs.push(message);

    try {
        application.selectNextPerson();
        assert(logs.includes('--select next person--'));

        application.selectNextPerson();
        assert(logs.includes('--select next person--'));

        const result = application.selectNextPerson();
        assert.strictEqual(result, null);
        assert(logs.includes('all selected'));
    } finally {
        console.log = originalLog;
    }
    Application.prototype.getNames = originalGetNames;
});


test('Testing notifySelected', async () => {
    const originalGetNames = Application.prototype.getNames;
    Application.prototype.getNames = async function() {
        return [['Alice', 'Bob'], ['Alice', 'Bob']];
    }

    const application = new Application();
    await new Promise((resolve) => setTimeout(resolve, 10));

    let writeCalls = [];
    let sendCalls = [];
    //Mocking mailSystem object
    application.mailSystem = {
        write: (name) => {
            writeCalls.push(name);
            return `Congrats, ${name}!`;
        },
        send: (name, context) => {
            sendCalls.push([name, context]);
        }
    };

    //Spying on console.log
    let logs = [];
    const originalLog = console.log;
    console.log = (message) => logs.push(message);

    try {
        application.notifySelected();
        assert(logs.includes('--notify selected--'));
        assert.deepStrictEqual(writeCalls, ['Alice', 'Bob']);
        assert.deepStrictEqual(sendCalls, [['Alice', 'Congrats, Alice!'], ['Bob', 'Congrats, Bob!']]);
    } finally {
        console.log = originalLog;
    }

    Application.prototype.getNames = originalGetNames;
});