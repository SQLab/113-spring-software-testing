const {describe, it, mock} = require('node:test');
const assert = require('assert');
const fs = require('fs');
fs.readFile = (fileName, options, callback) => {process.nextTick(() => callback(null, 'Alice\nBob\nCharlie'));};
const { Application, MailSystem} = require('./main');

// TODO: write your tests here
//test MailSystem
describe('write test',() => {
    it('return expected string', () => {
        const mailSystem = new MailSystem();
        assert.strictEqual(mailSystem.write('Bob'),'Congrats, Bob!');
    });
});
describe('send test',() => {
    it('success send', () => {
        const mailSystem = new MailSystem();
        const mockSuccess = mock.method(Math, 'random', () => 1.0);
        const result = mailSystem.send('Bob','Success')
        assert.strictEqual(result,true);
        mockSuccess.mock.restore();
    });
    it('fail send', () => {
        const mailSystem = new MailSystem();
        const mockFail = mock.method(Math, 'random', () => 0);
        const result = mailSystem.send('Bob','Fail')
        assert.strictEqual(result,false);
        mockFail.mock.restore();
    });
});
//test Application
describe('getNames test', () => {
    it('people & selected', async () => {
        const app = new Application();
        await app.getNames();
        assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
        assert.deepStrictEqual(app.selected, []);
    });
});
describe('selectNextPerson test', () => {
    it('remain one person',async  () => {
        const app = new Application();
        await app.getNames();
        app.selected = ['Alice', 'Bob'];
        assert.strictEqual(app.selectNextPerson(),'Charlie');
    });
    it('if all person selected', async () => {
        const app = new Application();
        await app.getNames();
        app.selected = ['Alice','Bob','Charile'];
        assert.strictEqual(app.selectNextPerson(),null);
    });
});
describe('notifySelected test', () => {
    it('no selected',  () => {
        const mailSystem = new MailSystem;
        const app = new Application();
        const mockWrite = mock.method(mailSystem, 'write', () => "Mocked Message");
        const mockSend = mock.method(mailSystem, 'send', () => "Mocked Send");
        app.mailSystem = mailSystem;
        app.notifySelected();
        assert.strictEqual(mockWrite.mock.calls.length,0);
        assert.strictEqual(mockSend.mock.calls.length,0);
    });
    it('selected all',async  () => {
        const mailSystem = new MailSystem;
        const app = new Application();
        const mockWrite = mock.method(mailSystem, 'write', () => "Mocked Message");
        const mockSend = mock.method(mailSystem, 'send', () => "Mocked Send");
        app.mailSystem = mailSystem;
        await app.getNames();
        app.selected = ['Alice','Bob','Charile'];
        app.notifySelected();
        assert.strictEqual(mockWrite.mock.calls.length,3);
        assert.strictEqual(mockSend.mock.calls.length,3);
        mockWrite.mock.restore();
        mockSend.mock.restore();
    });   
});
// Remember to use Stub, Mock, and Spy when necessary

