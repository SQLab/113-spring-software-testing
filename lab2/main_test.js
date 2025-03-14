const { test } = require('node:test');
const assert = require('node:assert');
const { Application, MailSystem } = require('./main.js');
const fs = require('fs');

/*
    function coverage testing:
    - MailSystem
        - write
        - send
    - Application
        - getNames
        - getRandomPerson
        - selectNextPerson
        - notifySelected
*/

test('MailSystem write test', (t) => {
    const mail = new MailSystem();
    const result = mail.write('Test');
    assert.equal(result, 'Congrats, Test!');
});

// Test Stub
test('MailSystem send test', (t) => {
    const mail = new MailSystem();
    const originalRandom = Math.random;
    
    // Test success case
    Math.random = () => 1;
    assert.equal(mail.send('Test', 'content'), true);
    
    // Test failure case
    Math.random = () => 0;
    assert.equal(mail.send('Test', 'content'), false);
    
    Math.random = originalRandom;
});

// Application tests
test('Application initialization test', async (t) => {
    // 準備測試檔案
    fs.writeFileSync('name_list.txt', 'Test1\nTest2\nTest3');
  
    try {
      const app = new Application();
      await new Promise(resolve => setTimeout(resolve, 100)); // 等待初始化完成
  
      assert(Array.isArray(app.people));
      assert(Array.isArray(app.selected));
      assert.equal(app.people.length, 3);
      assert.equal(app.selected.length, 0);
    } finally {
      // 清理測試檔案
      fs.unlinkSync('name_list.txt');
    }
});


test('Application selectNextPerson test', async (t) => {
    // 準備測試檔案
    fs.writeFileSync('name_list.txt', 'Test1\nTest2\nTest3');
  
    try {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 100)); // 等待初始化完成

        const person1 = app.selectNextPerson();
        assert(app.people.includes(person1));
        assert.equal(app.selected.length, 1);

        const person2 = app.selectNextPerson();
        assert(app.people.includes(person2));
        assert.equal(app.selected.length, 2);
        assert.notEqual(person1, person2);

        const person3 = app.selectNextPerson();
        assert(app.people.includes(person3));
        assert.equal(app.selected.length, 3);

        // 當所有人都被選中後，應該返回 null
        const person4 = app.selectNextPerson();
        assert.equal(person4, null);
    } finally {
        // 清理測試檔案
        fs.unlinkSync('name_list.txt');
    }
});


// Mock Object 
test('Application notifySelected test', async (t) => {
    // 準備測試檔案
    fs.writeFileSync('name_list.txt', 'Test1\nTest2');

    try {
        const app = new Application();
        await new Promise(resolve => setTimeout(resolve, 100)); // 等待初始化完成
        
        app.selectNextPerson(); // 選擇第一個人
        app.selectNextPerson(); // 選擇第二個人

        // Mock MailSystem methods
        let writeCount = 0;
        let sendCount = 0;
        app.mailSystem.write = (name) => {
        writeCount++;
        return `Congrats, ${name}!`;
        };
        app.mailSystem.send = (name, context) => {
        sendCount++;
        return true;
        };
        
        app.notifySelected();
        assert.equal(writeCount, 2);
        assert.equal(sendCount, 2);
    } finally {
        // 清理測試檔案
        fs.unlinkSync('name_list.txt');
    }
});


