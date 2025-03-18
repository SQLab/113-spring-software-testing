const test = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');

// // TODO: write your tests here
// // Remember to use Stub, Mock, and Spy when necessary
const fs = require('fs');
const path = require('path');

test('MailSystem should return the correct message context.', () => {
    const mailSystem = new MailSystem();
    const message = mailSystem.write('Justin');

    assert.strictEqual(message, 'Congrats, Justin!');
});

test('MailSystem should send mail corrctly', () => {
    const mailSystem = new MailSystem();

    // SUCCESSFUL CASE
	test.mock.method(Math,'random', () => 1);
    let isMailSent = mailSystem.send('Alice', "Hello Message");
    assert.strictEqual(isMailSent, true, 'Mail should be sent successfully when Math.random() returns 1');

    // FAIL CASE
    test.mock.method(Math, 'random', () => 0.5);
    isMailSent = mailSystem.send('Alice', "Hello Message");
    assert.strictEqual(isMailSent, false, 'Mail should fail to send when Math.random() returns a value less than 0.5');
});
 
test('Application should read names from file correctly', async()=>{
    const nameList = 'Alice\nBob\nCharlie\nSam';
    const filePath = path.resolve('name_list.txt');
    fs.writeFileSync(filePath, nameList);

    const app = new Application();
    const [names, selected] = await app.getNames(filePath);

    assert.deepStrictEqual(names, ['Alice', 'Bob', 'Charlie', 'Sam']);
    assert.deepStrictEqual(selected, []);
});
    
test('Application should return null when all people are selected', async (t) => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];
    app.selected = ['Alice', 'Bob', 'Charlie'];

    const selectedPerson = app.selectNextPerson();
    assert.strictEqual(selectedPerson, null);
});

test('Application should return a person randomly selected from the list', () => {
    Math.random = () => 0.2;
    
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];

    const selectedPerson = app.getRandomPerson();
    assert(app.people.includes(selectedPerson));
});

test('Application should ensure no person is selected more than once', () => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];

    let randomCallCount = 0;
    const people = ['Alice', 'Bob', 'Charlie'];
    app.getRandomPerson = () => people[randomCallCount++ % people.length];

    app.selected = ['Alice', 'Bob'];
    
    const nextSelectedPerson = app.selectNextPerson();
    assert.strictEqual(nextSelectedPerson, 'Charlie');
    assert.strictEqual(randomCallCount, 3);
});

test('Application should call write and send for each selected person', () => {
    const writeMock = test.mock.fn(() => 'Message context');
    const sendMock = test.mock.fn(() => true);

    const app = new Application();
    app.mailSystem.write = writeMock;
    app.mailSystem.send = sendMock;

    app.selected = ['Alice', 'Bob', 'Charlie'];

    app.notifySelected();

    assert.strictEqual(writeMock.mock.callCount(), 3);
    assert.strictEqual(sendMock.mock.callCount(), 3);
});