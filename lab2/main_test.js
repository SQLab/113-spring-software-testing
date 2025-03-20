const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { Application, MailSystem } = require('./main');

// ------------------------
// MailSystem 測試
// ------------------------

// 測試 MailSystem.write 方法
test('MailSystem.write returns correct context', () => {
  const mailSystem = new MailSystem();
  const context = mailSystem.write('Alice');
  assert.strictEqual(context, 'Congrats, Alice!');
});

// 測試 MailSystem.send 成功分支（利用 stub 改寫 Math.random）
test('MailSystem.send returns true when mail is sent', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.6; // 0.6 > 0.5 表示成功
  const result = mailSystem.send('Alice', 'dummy context');
  assert.strictEqual(result, true);
  Math.random = originalRandom;
});

// 測試 MailSystem.send 失敗分支
test('MailSystem.send returns false when mail fails', () => {
  const mailSystem = new MailSystem();
  const originalRandom = Math.random;
  Math.random = () => 0.4; // 0.4 <= 0.5 表示失敗
  const result = mailSystem.send('Alice', 'dummy context');
  assert.strictEqual(result, false);
  Math.random = originalRandom;
});

// ------------------------
// Application 測試
// ------------------------

// 測試 Application.getNames (透過實際建立暫存檔案)
test('Application.getNames reads file and returns names array', async () => {
  // 準備暫存檔案
  const fileContent = 'Alice\nBob\nCharlie';
  fs.writeFileSync('name_list.txt', fileContent, 'utf8');

  // 建立 Application 實例，利用原始 getNames 方法讀取檔案
  const app = new Application();
  // 因為 getNames 為非同步呼叫，等待一個 tick
  await new Promise(resolve => setTimeout(resolve, 10));

  // 驗證從檔案讀取的結果
  assert.deepStrictEqual(app.people, ['Alice', 'Bob', 'Charlie']);
  assert.deepStrictEqual(app.selected, []);
  
  // 清除暫存檔案
  fs.unlinkSync('name_list.txt');
});

// 測試 selectNextPerson
test('Application.selectNextPerson works correctly', async () => {
  // 使用 stub 覆寫 getNames，避免讀檔
  const originalGetNames = Application.prototype.getNames;
  Application.prototype.getNames = async function() {
    return [['Alice', 'Bob'], []];
  };

  const app = new Application();
  await new Promise(resolve => setTimeout(resolve, 10));

  // 使用一個預先定義的序列來控制 getRandomPerson 的回傳值
  let values = ['Alice', 'Alice', 'Bob'];
  let index = 0;
  app.getRandomPerson = () => values[index++];

  // 第一次呼叫：selected 為空，應回傳 "Alice"
  const person1 = app.selectNextPerson();
  assert.strictEqual(person1, 'Alice');

  // 第二次呼叫：第一次 getRandomPerson 回傳 "Alice"（已選取），接著回傳 "Bob"
  const person2 = app.selectNextPerson();
  assert.strictEqual(person2, 'Bob');

  // 第三次呼叫：已經選取完所有人，應回傳 null
  const person3 = app.selectNextPerson();
  assert.strictEqual(person3, null);

  // 還原 getNames
  Application.prototype.getNames = originalGetNames;
});

// 測試 notifySelected：利用 Spy 監控 mailSystem.write 與 send 被呼叫的情形
test('Application.notifySelected calls mailSystem.write and send for each selected', async () => {
  // 使用 stub 覆寫 getNames，使 selected 預先有資料
  const originalGetNames = Application.prototype.getNames;
  Application.prototype.getNames = async function() {
    return [['Alice', 'Bob'], ['Alice', 'Bob']];
  };

  const app = new Application();
  await new Promise(resolve => setTimeout(resolve, 10));

  // 建立 spy：紀錄 write 與 send 被呼叫的參數
  let writeCalls = [];
  let sendCalls = [];
  app.mailSystem.write = (name) => {
    writeCalls.push(name);
    return 'context_' + name;
  };
  app.mailSystem.send = (name, context) => {
    sendCalls.push({ name, context });
    return true;
  };

  app.notifySelected();

  // 驗證對每個 selected 皆呼叫 write 與 send
  assert.deepStrictEqual(writeCalls, ['Alice', 'Bob']);
  assert.deepStrictEqual(sendCalls, [
    { name: 'Alice', context: 'context_Alice' },
    { name: 'Bob', context: 'context_Bob' }
  ]);

  Application.prototype.getNames = originalGetNames;
});
