const test = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');


const fs = require('fs');
const TestData = 'name_list.txt';

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

test('MailSystem should write mail correctly', (t) => {
    const writeMock = t.mock.fn(MailSystem.prototype.write);
    const context = writeMock('Alice');
    assert.strictEqual(context, 'Congrats, Alice!');
});

// test('MailSystem should write mail correctly', () => {
//     const mailSystem = new MailSystem();
//     const context = mailSystem.write('Alice');
//     assert.strictEqual(context, 'Congrats, Alice!');
// });

test('MailSystem should send mail correctly', (t) => {
    t.mock.method(Math, 'random').mock.mockImplementation(() => 0.6);
    const success = MailSystem.prototype.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(success, true);
    t.mock.method(Math, 'random').mock.mockImplementation(() => 0.4);
    const failure = MailSystem.prototype.send('Alice', 'Congrats, Alice!');
    assert.strictEqual(failure, false);
});


test('Application should read file correctly', async (t) => {

    fs.writeFileSync(TestData, 'Alice\nBob\nCharlie', 'utf8');

    const getNameMock = t.mock.fn(Application.prototype.getNames);
    const data = await getNameMock();

    assert.strictEqual(data[0].length, 3);
    assert.strictEqual(data[0][0], 'Alice');

    if (fs.existsSync(TestData)) {
        fs.unlinkSync(TestData);
    }
});

test('Application should get random person', async (t) => {
    const getNamesMock = t.mock.method(Application.prototype, 'getNames', async () => {
        return [['Alice', 'Bob', 'Charlie'], []];
    });
    const app = new Application();
    const person = await app.getNames();

    assert.strictEqual(getNamesMock.mock.callCount(), 2);

    const randomPerson = app.getRandomPerson();
    assert.strictEqual(app.people.includes(randomPerson), true);

});

test('Application should select next person', async (t) => {
    const getNamesMock = t.mock.method(Application.prototype, 'getNames', async () => {
        return [['Alice', 'Bob', 'Charlie'], []];
    });
    const app = new Application();
    const person = await app.getNames();

    const selectNextPerson = app.selectNextPerson();
    assert.strictEqual(app.selected.includes(selectNextPerson), true);
    app.selectNextPerson();
    app.selectNextPerson();
    console.log(app.selected);
    assert.strictEqual(app.selectNextPerson(), null);
});

test('Application should notify person', async (t) => {
    const nameList = ['Alice', 'Bob', 'Charlie'];
    t.mock.method(Application.prototype, 'getNames', async () => {
        return [nameList, []];
    });
    const app = new Application();
    await app.getNames();

    app.selected = nameList;
    const writeMock = t.mock.method(MailSystem.prototype, 'write', () => {
        return true;
    });
    const sendMock = t.mock.method(MailSystem.prototype, 'send', () => {
        return true;
    });
    app.notifySelected();
    assert.strictEqual(writeMock.mock.callCount(), app.selected.length);
    assert.strictEqual(sendMock.mock.callCount(), app.selected.length);
});
