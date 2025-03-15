const test = require('node:test');
const assert = require('assert');
const oriRandom = Math.random;
const fs = require('fs');
const oriReadFile = fs.readFile;
test.mock.method(fs, "readFile", (path, encoding, callback) => {
    callback(null, "Sandy\nMandy\nCindy");
});

const { Application, MailSystem } = require('./main');

test("Test MailSystem", () => {
    const mailSystem = new MailSystem();

    // write
    assert.strictEqual(mailSystem.write("Sandy"), "Congrats, Sandy!");

    // send
    test.mock.method(Math, "random", () => 0.6);
    assert.strictEqual(mailSystem.send('Sandy', 'hello'), true);
    test.mock.method(Math, "random", () => 0.1);
    assert.strictEqual(mailSystem.send('Sandy', 'hello'), false);
});

test("Test Application", async () => {

    const app = new Application();
    const [people, select] = await app.getNames();
    assert.deepStrictEqual(people, ["Sandy", "Mandy", "Cindy"]);

    // getRandomPerson
    test.mock.method(Math, "random", () => 0.1);
    assert.strictEqual(app.getRandomPerson(), "Sandy");
    test.mock.method(Math, "random", () => 0.5);
    assert.strictEqual(app.getRandomPerson(), "Mandy");
    test.mock.method(Math, "random", () => 0.9);
    assert.strictEqual(app.getRandomPerson(), "Cindy");

    // selectNextPerson
    test.mock.method(Math, "random", () => 0.1);
    assert.strictEqual(app.selectNextPerson(), "Sandy");

    test.mock.method(Math, "random", () => oriRandom);
    test.mock.method(Math, "random", () => {    
        Math.random = oriRandom;
        return 0.1
    });
    assert.notEqual(app.selectNextPerson(), "Sandy");
    app.selectNextPerson();
    assert.strictEqual(app.selectNextPerson(), null);
    
    // notifySelected
    const sendMock = test.mock.method(MailSystem.prototype, 'send');
    assert.strictEqual(sendMock.mock.callCount(), 0);
    app.notifySelected()
    assert.strictEqual(sendMock.mock.callCount(), 3);

});
