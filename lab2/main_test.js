const test = require('node:test');
const assert = require('assert');
const fs = require('fs');

// ensure "Application" is imported after mocking fs.readFile
test.mock.method(fs, "readFile", (path, encoding, callback) => {
    callback(null, "Alice\nBob\nCharlie");
});

const { Application, MailSystem } = require('./main');

// MailSystem Tests
test('Test MailSystem.write', () => {
    const ms = new MailSystem();

    assert.strictEqual(ms.write("Alice"), 'Congrats, Alice!');
    assert.strictEqual(ms.write(10), 'Congrats, 10!');
    assert.strictEqual(ms.write(true), 'Congrats, true!');
    assert.strictEqual(ms.write("Bob"), 'Congrats, Bob!');
});

test("Test MailSystem.send", () => {
	const ms = new MailSystem();
	const name = "Alice";
	const context = "Congrats, Alice!";

	test.mock.method(Math, "random", () => 0.6);
	assert.strictEqual(ms.send(name, context), true);
	test.mock.method(Math, "random", () => 0.5);
	assert.strictEqual(ms.send(name, context), false);
});

// Application Tests
test('Test Application.getNames', async () => {
    const app = new Application();
    const [people, selected] = await app.getNames();
    assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(selected, []);
});

test('Test Application.getRandomPerson', () => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];

    test.mock.method(Math, "random", () => 0.1); // Index 0
	assert.strictEqual(app.getRandomPerson(), 'Alice');
	
	test.mock.method(Math, "random", () => 0.4); // Index 1
	assert.strictEqual(app.getRandomPerson(), 'Bob');
	
	test.mock.method(Math, "random", () => 0.8); // Index 2
	assert.strictEqual(app.getRandomPerson(), 'Charlie');
});

test('Test Application.selectNextPerson', () => {
    const app = new Application();
    app.people = ['Alice', 'Bob', 'Charlie'];
    app.selected = ['Alice'];

	let i = 0;
	test.mock.method(app, 'getRandomPerson', () => {
		if (i == 0) {
			i++;
			return 'Alice';
		}
		else if (i == 1) {
			i++;
			return 'Bob';
		}
		else{
			return 'Charlie';
		}
	})

	assert.strictEqual(app.selectNextPerson(), 'Bob');
	assert.deepStrictEqual(app.selected, ['Alice', 'Bob']);
	
	assert.strictEqual(app.selectNextPerson(), 'Charlie');
	assert.deepStrictEqual(app.selected, ['Alice', 'Bob', 'Charlie']);
	
	assert.strictEqual(app.selectNextPerson(), null);
});

test("Test Application.notifySelected", () => {
	const app = new Application();

	app.people = ['Alice', 'Bob', 'Charlie'];
	app.selected = ['Alice', 'Bob', 'Charlie'];

    const writeSpy = test.mock.fn(app.mailSystem.write);
    const sendSpy = test.mock.fn(app.mailSystem.send);

    app.mailSystem.write = writeSpy;
    app.mailSystem.send = sendSpy;

    app.notifySelected();

    assert.strictEqual(writeSpy.mock.calls.length, 3);
    assert.strictEqual(sendSpy.mock.calls.length, 3);

    assert.strictEqual(writeSpy.mock.calls[0].arguments[0], 'Alice');
    assert.strictEqual(writeSpy.mock.calls[1].arguments[0], 'Bob');
    assert.strictEqual(writeSpy.mock.calls[2].arguments[0], 'Charlie');

    assert.strictEqual(sendSpy.mock.calls[0].arguments[0], 'Alice');
    assert.strictEqual(sendSpy.mock.calls[1].arguments[0], 'Bob');
    assert.strictEqual(sendSpy.mock.calls[2].arguments[0], 'Charlie');
});