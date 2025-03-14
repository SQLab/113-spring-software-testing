import fs from 'fs';
import path from 'path';
import os from 'os';
import test from 'node:test';
import assert from 'assert';
import { Application, MailSystem } from './main.js';

// 輔助函式：在暫存目錄中建立 name_list.txt，並切換工作目錄
async function withTempNameList(fn) {
  const originalCwd = process.cwd();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab2-'));
  fs.writeFileSync(path.join(tmpDir, 'name_list.txt'), 'Alice\nBob\nCharlie');
  process.chdir(tmpDir);
  try {
    await fn();
  } finally {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// 建立 Stub 輔助函式
const createStub = (obj, method, implementation) => {
  const original = obj[method];
  obj[method] = implementation;
  return { restore: () => { obj[method] = original; } };
};

// 測試 MailSystem.write()（不需要檔案）
test('MailSystem.write should generate correct mail content', () => {
  const mailSystem = new MailSystem();
  const result = mailSystem.write('Alice');
  assert.strictEqual(result, 'Congrats, Alice!');
});

// 測試 MailSystem.send()：透過 stub 控制隨機行為
test('MailSystem.send should return success or failure', () => {
  const mailSystem = new MailSystem();
  const randomStub = createStub(Math, 'random', () => 0.9);
  assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), true);
  randomStub.restore();
  const randomStub2 = createStub(Math, 'random', () => 0.4);
  assert.strictEqual(mailSystem.send('Alice', 'Congrats, Alice!'), false);
  randomStub2.restore();
});

// 以下測試皆需要 name_list.txt，所以採用 withTempNameList 包裹

test('Application.getNames should read and parse names from file', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    // 等待 constructor 的非同步初始化完成
    await new Promise(resolve => setTimeout(resolve, 10));
    const [people, selected] = await app.getNames();
    assert.deepStrictEqual(people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(selected, []);
  });
});

test('Application constructor should initialize people and selected', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
    assert.deepStrictEqual(app.selected, []);
  });
});

test('Application.getRandomPerson should return a person from people list', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    // stub Math.random 固定回傳 0.5 (floor(0.5 * 3) = 1) → 'Bob'
    const randomStub = createStub(Math, 'random', () => 0.5);
    assert.strictEqual(app.getRandomPerson(), 'Bob');
    randomStub.restore();
  });
});

test('Application.selectNextPerson should select a unique person in order', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    // stub getRandomPerson 依序回傳：'Alice', 'Bob', 'Charlie'
    let sequence = ['Alice', 'Bob', 'Charlie'];
    let index = 0;
    const stub = createStub(app, 'getRandomPerson', () => sequence[index++]);
    
    const selected1 = app.selectNextPerson();
    assert.strictEqual(selected1, 'Alice');
    assert.strictEqual(app.selected.length, 1);
    
    const selected2 = app.selectNextPerson();
    assert.strictEqual(selected2, 'Bob');
    assert.strictEqual(app.selected.length, 2);
    
    const selected3 = app.selectNextPerson();
    assert.strictEqual(selected3, 'Charlie');
    assert.strictEqual(app.selected.length, 3);
    
    const selected4 = app.selectNextPerson();
    assert.strictEqual(selected4, null);
    
    stub.restore();
  });
});

test('Application.selectNextPerson should retry if duplicate selected', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    // stub 模擬第一次回傳 'Alice'（已被選取），接著回傳 'Bob'
    let callCount = 0;
    const stub = createStub(app, 'getRandomPerson', () => {
      if (callCount === 0) {
        callCount++;
        return 'Alice';
      }
      return 'Bob';
    });
    // 預先將 'Alice' 加入已選名單
    app.selected = ['Alice'];
    const result = app.selectNextPerson();
    assert.strictEqual(result, 'Bob');
    stub.restore();
  });
});

test('Application.notifySelected should send mail to selected people', async () => {
  await withTempNameList(async () => {
    const app = new Application();
    await new Promise(resolve => setTimeout(resolve, 10));
    app.selected = ['Alice', 'Bob'];
    let writeCalls = [];
    let sendCalls = [];
    const writeStub = createStub(app.mailSystem, 'write', (name) => {
      writeCalls.push(name);
      return `Congrats, ${name}!`;
    });
    const sendStub = createStub(app.mailSystem, 'send', (name, content) => {
      sendCalls.push({ name, content });
      return true;
    });
    
    app.notifySelected();
    
    assert.deepStrictEqual(writeCalls, ['Alice', 'Bob']);
    assert.deepStrictEqual(sendCalls, [
      { name: 'Alice', content: 'Congrats, Alice!' },
      { name: 'Bob', content: 'Congrats, Bob!' }
    ]);
    
    writeStub.restore();
    sendStub.restore();
  });
});
