const test = require('node:test');
const assert = require('assert');
const { Application, MailSystem } = require('./main');
const sinon = require('sinon');

test('test getRandomPerson in main.js', async () => {
  const app = new Application();

  app.getNames = async () => {
    app.people = ['Annika', 'Billy', 'Cecilia'];
  };

  await app.getNames();

  const person = app.getRandomPerson();
  assert.ok(app.people.includes(person), 'the person is not in list');
});

test('test mains selectNextPerson to not select same person twice', async () => {
  const app = new Application();

  app.getNames = async () => {
    app.people = ['Annika', 'Billy', 'Cecilia'];
    app.selected = [];
  };

  await app.getNames();

  const person1 = app.selectNextPerson();
  const person2 = app.selectNextPerson();

  assert.notStrictEqual(person1, person2, 'Same person was selected twice');
});

test('test mains notifySelected that it calls send()', async () => {
  const mailSystem = new MailSystem();
  const sendSpy = sinon.spy(mailSystem, 'send');

  const app = new Application();
  app.mailSystem = mailSystem;

  app.getNames = async () => {
    app.people = ['Annika', 'Billy', 'Cecilia'];
    app.selected = [];
  };

  await app.getNames();

  const person = app.selectNextPerson();
  app.selected = [person];

  await app.notifySelected();

  assert.ok(
    sendSpy.calledWith(person, `Congrats, ${person}!`),
    `send() didn't work with args. Captured calls: ${JSON.stringify(sendSpy.args)}`
  );
});
