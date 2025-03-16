const test = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');
const { write } = require('fs');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary

test('MailSystem.write', () => {
    const mailSystem = new MailSystem();
    const result = mailSystem.write('John');
    assert.strictEqual(result, 'Congrats, John!');

    const result_2 = mailSystem.write('Jane');
    assert.strictEqual(result_2, 'Congrats, Jane!');
})

test('MailSystem.send success', (t) => {
    const mailSystem = new MailSystem();
    const restoreRandom = Math.random;
    Math.random = () => 0.8;
    const result = mailSystem.send('John', 'Test Message');
    assert.strictEqual(result, true);
    Math.random = restoreRandom;
})

test('MailSystem.send NOT success', (t) => {
    const mailSystem = new MailSystem();
    const restoreRandom = Math.random;
    Math.random = () => 0.5;
    const result = mailSystem.send('John', 'Test Message');
    assert.strictEqual(result, false);
    Math.random = restoreRandom;
})

test('Application.getNames stub', async () => {
    const app = Object.create(Application.prototype);
    app.getNames = async () => [['John', 'Jane', 'Doe'], []];

    const [people, selected] = await app.getNames();
    app.people = people;
    app.selected = selected;

    assert.deepStrictEqual(app.people, ['John', 'Jane', 'Doe']);
    assert.deepStrictEqual(app.selected, []);
});

test('Application.getRandomPerson', () => {
    const app = Object.create(Application.prototype);
    app.people = ['John', 'Jane', 'Doe'];
    const person_1 = app.getRandomPerson();
    assert.ok(app.people.includes(person_1));

    const restoreRandom = Math.random;
    Math.random = () => 0.3;
    const i = Math.floor(Math.random() * 3);
    assert.deepStrictEqual(app.people[i], 'John')
    Math.random = restoreRandom;
});

test('Application.selectNextPerson return person', () => {
    const app = Object.create(Application.prototype);
    app.people = ['John', 'Jane', 'Doe'];
    app.selected = [];

    const first = app.selectNextPerson();
    assert.ok(app.people.includes(first));
    assert.strictEqual(app.selected.includes(first), true);

    const second = app.selectNextPerson();
    assert.ok(app.people.includes(second));
    assert.notStrictEqual(first, second);
    assert.strictEqual(app.selected.includes(second), true);
})

test('Application.selectNextPerson returns null', () => {
    const app = Object.create(Application.prototype);
    app.people = ['John', 'Jane'];
    app.selected = ['John', 'Jane']; // already all selected
    const result = app.selectNextPerson();
    assert.strictEqual(result, null);
});

test('Application.selectNextPerson retries(the person was already selected)', () => {
    const app = Object.create(Application.prototype);
    app.people = ['John', 'Jane', 'Doe'];
    app.selected = ['Jane'];

    // stub getRandomPerson：第一次回傳已被選的 Jane，第二次回傳 John
    let callCount = 0;
    app.getRandomPerson = () => {
        callCount++;
        return callCount === 1 ? 'Jane' : 'John';
    };

    const selected = app.selectNextPerson();
    assert.strictEqual(selected, 'John');
    assert.deepStrictEqual(app.selected, ['Jane', 'John']);
});

test('Application.notifySelected', () => {
    const app = Object.create(Application.prototype);
    app.people = ['John', 'Jane', 'Doe'];
    app.selected = ['Jane', 'Doe'];

    //spy
    const writeCalled = [];
    const sendCalled = [];

    app.mailSystem = {
        write: (name) => {
            writeCalled.push(name);
            return `Stubbed mail for ${name}`;
        },
        send: (name, context) => {
            sendCalled.push({ name, context });
            return true;
        }
    };

    app.notifySelected();

    //檢查write & send是否對每位selected都執行過
    assert.deepStrictEqual(writeCalled, ['Jane', 'Doe']);
    assert.deepStrictEqual(sendCalled, [
        { name: 'Jane', context: 'Stubbed mail for Jane' },
        { name: 'Doe', context: 'Stubbed mail for Doe' }
    ]);
});

const fs = require('fs');
const path = require('path');

test('Application constructor and getNames() are covered (with real file)', async () => {
    //動態建立name_list.txt
    const filename = 'name_list.txt';
    fs.writeFileSync(filename, 'John\nJane\nDoe', 'utf8');

    //constructor 會執行 getNames()
    const app = new Application();

    //等待async初始化
    await new Promise(resolve => setTimeout(resolve, 10));

    assert.deepStrictEqual(app.people, ['John', 'Jane', 'Doe']);
    assert.deepStrictEqual(app.selected, []);

    //清除 name_list.txt
    fs.unlinkSync(filename);
});