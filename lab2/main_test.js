const test = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');

// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary
test('Mocks The mail system', (t) =>{

    const mail = new MailSystem();
    const name = "John"
    t.mock.method(mail, 'write');
    assert.strictEqual(mail.write.mock.callCount(), 0);
    assert.strictEqual(mail.write(name), 'Congrats, ' + name + '!');
    assert.strictEqual(mail.write.mock.callCount(), 1);
    
    const originalRandom = Math.random;
    Math.random = () => 0.8;

    const context = "Congrats"
    t.mock.method(mail, 'send');
    assert.strictEqual(mail.send.mock.callCount(), 0);
    assert.strictEqual(mail.send(name, context), true);
    assert.strictEqual(mail.send.mock.callCount(), 1);

    Math.random = originalRandom;
})

test('Mocks the app system', async (t) => {
    fs.writeFileSync('name_list.txt', 'A\nB\nC');

    const app = new Application();

    await new Promise(resolve => setTimeout(resolve, 50));

    assert.deepStrictEqual(app.people, ['A', 'B', 'C']);
    assert.deepStrictEqual(app.selected, []);
    assert.strictEqual(app.selected.length, 0);

    const originalRandom = Math.random;
    Math.random = () => 0.1;
    t.mock.method(app, 'getRandomPerson');
    assert.strictEqual(app.getRandomPerson.mock.callCount(), 0);
    assert.strictEqual(app.getRandomPerson(), 'A');
    assert.strictEqual(app.getRandomPerson.mock.callCount(), 1);

    t.mock.method(app, 'selectNextPerson');
    assert.strictEqual(app.selectNextPerson.mock.callCount(), 0);
    assert.strictEqual(app.selectNextPerson(), 'A');
    assert.strictEqual(app.selectNextPerson.mock.callCount(), 1);

    Math.random = () => 0.4;
    assert.strictEqual(app.selectNextPerson(), 'B');
    assert.strictEqual(app.selectNextPerson.mock.callCount(), 2);

    Math.random = () => 0.7;
    assert.strictEqual(app.selectNextPerson(), 'C');
    assert.strictEqual(app.selectNextPerson.mock.callCount(), 3);

    assert.strictEqual(app.selectNextPerson(), null);
    assert.strictEqual(app.selectNextPerson.mock.callCount(), 4);

    t.mock.method(app, 'notifySelected');
    assert.strictEqual(app.notifySelected.mock.callCount(), 0);
    app.notifySelected();
    assert.strictEqual(app.notifySelected.mock.callCount(), 1);

    Math.random = originalRandom;
    fs.unlinkSync('name_list.txt');
});
