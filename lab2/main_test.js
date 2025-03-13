const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

test.mock.method(fs, 'readFile', (path,encoding,callback)=>{callback(0,'Alice\nBob\nCharlie')});
const { Application, MailSystem } = require('./main');
test('Test MailSystem write', () => {
    const testmail = new MailSystem();
    assert.deepStrictEqual(testmail.write('Alice'), 'Congrats, ' + 'Alice' + '!');
});
test('Test MailSystem send', () => {
    const testmail = new MailSystem();
    test.mock.method(Math,'random',() => true);
    assert.deepStrictEqual(testmail.send('Alice', 'success'), true);
    test.mock.method(Math,'random',() => false);
    assert.deepStrictEqual(testmail.send('Alice', 'fail'), false);
});

test('Test Application constructor', async () => {
    const app = new Application();
    await app.getNames();
    assert.deepStrictEqual(app.people, ['Alice','Bob','Charlie']);
    assert.deepStrictEqual(app.selected, []);
});


test('Test Application getRandomPerson', async () => {
    const app = new Application();
    await app.getNames();
    test.mock.method(Math,'random',() => 0);
    assert.deepStrictEqual(app.getRandomPerson(), app.people[0]);
});

test('Test Application selectNextPerson', async () => {
    const app = new Application();
    await app.getNames();
    let i = 0;
    test.mock.method(app, 'getRandomPerson', ()=>{
        return app.people[i++]});
    assert.deepStrictEqual(app.selectNextPerson(), app.people[0]);
    i = 0;
    assert.deepStrictEqual(app.selectNextPerson(), app.people[1]);
    app.selected = [0, 0, 0];
    assert.deepStrictEqual(app.selectNextPerson(), null);
});

test('Test Application notifySelected()', async () => {
    const app = new Application();
    await app.getNames();
    app.selected = ['Alice'];
    assert.deepStrictEqual(app.notifySelected(), undefined);
});