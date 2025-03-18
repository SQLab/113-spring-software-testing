const { mock, test } = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
// TODO: write your tests here
// Remember to use Stub, Mock, and Spy when necessary
async function withTempNameList(fn) {
    const originalCwd = process.cwd();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab2-'));
    fs.writeFileSync(path.join(tmpDir, 'name_list.txt'), 'Yukimura\nAnonymouself\nPing');
    process.chdir(tmpDir);
    try {
      await fn();
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
  
  // Test: MailSystem.write() should correctly format the mail content
  test('MailSystem.write should create an expected mail message', () => {
    const mailSystem = new MailSystem();
    const result = mailSystem.write('Yukimura');
    assert.strictEqual(result, 'Congrats, Yukimura!');
  });
  
  // Test: MailSystem.send() should return a predictable outcome based on randomness
  test('MailSystem.send should correctly reflect success or failure', () => {
    const mailSystem = new MailSystem();
    mock.method(Math, 'random', () => 0.9);
    assert.strictEqual(mailSystem.send('Yukimura', 'Congrats, Yukimura!'), true);
    
    mock.method(Math, 'random', () => 0.4);
    assert.strictEqual(mailSystem.send('Yukimura', 'Congrats, Yukimura!'), false);
  });
  
  // Test: Application.getNames() should correctly read and parse the name list
  test('Application.getNames should load and split names correctly from file', async () => {
    await withTempNameList(async () => {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 10));
      const [people, selected] = await app.getNames();
      assert.deepStrictEqual(people, ['Yukimura', 'Anonymouself', 'Ping']);
      assert.deepStrictEqual(selected, []);
    });
  });
  
  // Test: Application.getRandomPerson() should return a valid name from the list
  test('Application.getRandomPerson should return an existing person from the list', async () => {
    await withTempNameList(async () => {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 10));
      mock.method(Math, 'random', () => 0.5);
      const person = app.getRandomPerson();
      assert.strictEqual(['Yukimura', 'Anonymouself', 'Ping'].includes(person), true);
    });
  });
  
  // Test: Application.selectNextPerson should avoid duplicates and return null if all are selected
  test('Application.selectNextPerson should reattempt if a duplicate is selected and return null when exhausted', async () => {
    await withTempNameList(async () => {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 10));
      
      app.selected = ['Yukimura', 'Anonymouself', 'Ping'];
      const result = app.selectNextPerson();
      assert.strictEqual(result, null);
      assert.strictEqual(app.selected.length, 3);
    });
    
    await withTempNameList(async () => {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 10));
      
      app.selected = ['Yukimura'];
      let callCount = 0;
      mock.method(app, 'getRandomPerson', () => {
        if (callCount === 0) {
          callCount++;
          return 'Yukimura'; // Simulate first selection returning an already chosen name
        }
        return 'Anonymouself'; // Second attempt should return a new name
      });
      
      const result = app.selectNextPerson();
      assert.strictEqual(result, 'Anonymouself');
      assert.strictEqual(app.selected.length, 2);
    });
  });
  
  // Test: Application.notifySelected() should trigger notifications for all selected users
  test('Application.notifySelected should generate and send mail to each selected individual', async () => {
    await withTempNameList(async () => {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 10));
      app.selected = ['Yukimura', 'Anonymouself'];
      
      const writeMock = mock.fn((name) => `Congrats, ${name}!`);
      const sendMock = mock.fn(() => true);
      mock.method(app.mailSystem, 'write', writeMock);
      mock.method(app.mailSystem, 'send', sendMock);
      
      app.notifySelected();
      
      assert.strictEqual(writeMock.mock.calls.length, 2);
      assert.strictEqual(sendMock.mock.calls.length, 2);
      assert.strictEqual(writeMock.mock.calls[0].arguments[0], 'Yukimura');
      assert.strictEqual(writeMock.mock.calls[1].arguments[0], 'Anonymouself');
      assert.strictEqual(sendMock.mock.calls[0].arguments[0], 'Yukimura');
      assert.strictEqual(sendMock.mock.calls[1].arguments[0], 'Anonymouself');
    });
  });
  