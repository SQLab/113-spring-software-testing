const assert = require('assert');
const { mock, test } = require('node:test');
const fs = require('fs');
mock.method(fs, 'readFile', (path, encoding, callback) => {
    callback(null, 'A\nB\nC');
  });
const { Application, MailSystem } = require('./main');

// Remember to use Stub, Mock, and Spy when necessary
async function createApplication() {
    const app = new Application();
    // Wait for the promise in the constructor to resolve
    await new Promise(resolve => {
      const checkIfLoaded = () => {
        if (app.people.length > 0) {
          resolve();
        } else {
          setTimeout(checkIfLoaded, 10);
        }
      };
      checkIfLoaded();
    });
    return app;
  }

// MailSystem Tests
test('MailSystem.write returns correct message', (t) => {
    const mailSystem = new MailSystem();
    const name = 'Test User';
    const expected = 'Congrats, Test User!';
    const result = mailSystem.write(name);
    assert.strictEqual(result, expected);
  // Test that the write method returns the expected message
  // No stubbing needed here - simple unit test
});

test('MailSystem.send returns success based on random value', (t) => {
  // Use Stub to control Math.random() to test both success and failure cases
  // Test both success (>0.5) and failure (<=0.5) scenarios
  const mailSystem = new MailSystem();
  t.mock.method(Math, 'random', () => 0.75);
  const result = mailSystem.send('Test User', 'test context');
  assert.strictEqual(result, true);

  t.mock.method(Math, 'random', () => 0.25);
  const result2 = mailSystem.send('Test User', 'test context');
  assert.strictEqual(result2, false);
});

// Application Tests
test('Application constructor initializes properties correctly', async (t) => {
  // Use Stub for readFile to control file content
  // Test that people/selected arrays are initialized correctly
  const application = await createApplication();
  assert.deepStrictEqual(application.people, ['A', 'B', 'C']);
  assert.deepStrictEqual(application.selected, []);
});


test('Application.getRandomPerson returns a person from people array', async (t) => {
  // Prepare an application with known people
  // Use Stub for Math.random to control which person is selected
  // Assert the correct person is returned
  const application = await createApplication();
  t.mock.method(Math, 'random', () => 0.0);
  const result1 = application.getRandomPerson();
  assert.strictEqual(result1, 'A');
  t.mock.method(Math, 'random', () => 0.5);
  const result2 = application.getRandomPerson();
  assert.strictEqual(result2, 'B');
  t.mock.method(Math, 'random', () => 0.9);
  const result3 = application.getRandomPerson();
  assert.strictEqual(result3, 'C');
});

test('Application.selectNextPerson selects a person not previously selected', async (t) => {
  // Use Stub for getRandomPerson to control selection
  // Assert person is added to selected array and returned
  const application = await createApplication();
  
  // First, add 'A' to selected array
  application.selected = ['A'];
  
  // Mock getRandomPerson to return 'A' first (already selected), then 'B'
  let callCount = 0;
  t.mock.method(application, 'getRandomPerson', () => {
    callCount++;
    return callCount === 1 ? 'A' : 'B';
  });
  
  const result = application.selectNextPerson();
  
  // Should return 'B' after skipping 'A' which was already selected
  assert.strictEqual(result, 'B');
  assert.deepStrictEqual(application.selected, ['A', 'B']);
  assert.strictEqual(callCount, 2, 'getRandomPerson should be called twice');
});

test('Application.selectNextPerson returns null when all people are selected', async (t) => {
  // Create an Application where people.length === selected.length
  // Assert that null is returned
  const application = await createApplication();
  
  // Manually set selected to contain all people
  application.selected = ['A', 'B', 'C'];
  
  const result = application.selectNextPerson();
  
  assert.strictEqual(result, null);
});

test('Application.notifySelected calls mailSystem methods for each selected person', async (t) => {
  // Verify these methods are called for each selected person
  const application = await createApplication();
  application.selected = ['A', 'B']; // Set selected people
  
  // Create spies for mailSystem methods
  const writeSpy = t.mock.method(application.mailSystem, 'write');
  const sendSpy = t.mock.method(application.mailSystem, 'send');
  
  // Execute the method being tested
  application.notifySelected();
  
  // Verify write was called for each selected person
  assert.strictEqual(writeSpy.mock.calls.length, 2);
  assert.deepStrictEqual(writeSpy.mock.calls[0].arguments, ['A']);
  assert.deepStrictEqual(writeSpy.mock.calls[1].arguments, ['B']);
  
  // Verify send was called for each selected person
  assert.strictEqual(sendSpy.mock.calls.length, 2);
  assert.deepStrictEqual(sendSpy.mock.calls[0].arguments[0], 'A');
  assert.deepStrictEqual(sendSpy.mock.calls[1].arguments[0], 'B');
});

