const fs = require('fs');
const originalReadFile = fs.readFile;

fs.readFile = (path, encoding, callback) => {
    process.nextTick(() => callback(null, 'Alice\nBob\nCharlie'));
};

const { Application, MailSystem } = require('./main');

const assert = require('assert');
const { describe, it, afterEach, after, mock } = require('node:test');

describe('Application', () => {
    afterEach(() => {
        mock.reset();
    });

    it('should load names from file correctly', async () => {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 50));

        assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
        assert.deepStrictEqual(app.selected, []);
    });

    it('should select a unique person correctly', async () => {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 50));

        const person = app.selectNextPerson();
        assert.ok(app.people.includes(person));
        assert.ok(app.selected.includes(person));
    });

    it('should return null if all persons are already selected', async () => {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 50));
        app.selected = [...app.people];
        const person = app.selectNextPerson();
        assert.strictEqual(person, null);
    });

    it('should retry getRandomPerson if initial selection is duplicate', async () => {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 50));
        app.people = ['Alice', 'Bob', 'Charlie'];
        app.selected = ['Alice'];

        let callCount = 0;
        app.getRandomPerson = () => {
            callCount++;
            return callCount === 1 ? 'Alice' : 'Bob';
        };

        const person = app.selectNextPerson();
        assert.strictEqual(person, 'Bob');
        assert.ok(app.selected.includes('Bob'));
    });

    it('notifySelected interacts correctly with MailSystem', async () => {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 50));

        app.selected = ['Alice', 'Bob'];

        const writeMock = mock.method(app.mailSystem, 'write', () => 'test context');
        const sendMock = mock.method(app.mailSystem, 'send', () => true);

        app.notifySelected();

        assert.strictEqual(writeMock.mock.calls.length, 2);
        assert.strictEqual(sendMock.mock.calls.length, 2);
    });
});

describe('MailSystem', () => {
    const mail = new MailSystem();

    it('write generates correct context', () => {
        const context = mail.write('Alice');
        assert.strictEqual(context, 'Congrats, Alice!');
    });

    it('send should return success or failure', () => {
        const randomMock = mock.method(Math, 'random', () => 0.6);
        assert.strictEqual(mail.send('Alice', 'Context'), true);

        randomMock.mock.restore();
        mock.method(Math, 'random', () => 0.4);
        assert.strictEqual(mail.send('Alice', 'Context'), false);
    });
});

after(() => {
    fs.readFile = originalReadFile;
});
