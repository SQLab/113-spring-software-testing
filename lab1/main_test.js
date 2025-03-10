const test = require('node:test')
const assert = require('assert');
const { MyClass, Student } = require('./main.js'); // 將 your-file-name 替換為你的檔案名稱

test.beforeEach((context) => {
  context.myClass = new MyClass();
  context.student = new Student();
});

test('MyClass: should add a student and return the correct index', (context) => {
  const index = context.myClass.addStudent(context.student);
  assert.strictEqual(index, 0);
});

test('MyClass: should return -1 when adding a non-student object', (context) => {
  const nonStudent = {};
  const result = context.myClass.addStudent(nonStudent);
  assert.strictEqual(result, -1);
});

test('MyClass: should get a student by id', (context) => {
  context.myClass.addStudent(context.student);
  const retrievedStudent = context.myClass.getStudentById(0);
  assert.strictEqual(retrievedStudent, context.student);
});

test('MyClass: should return null when getting a student with an invalid id', (context) => {
  assert.strictEqual(context.myClass.getStudentById(-1), null);
  assert.strictEqual(context.myClass.getStudentById(1), null);
});

test('Student: should set the student name', (context) => {
  context.student.setName('John Doe');
  assert.strictEqual(context.student.getName(), 'John Doe');
});

test('Student: should not set the student name if it is not a string', (context) => {
  context.student.setName(123);
  assert.strictEqual(context.student.getName(), '');
});

test('Student: should return an empty string if the name is undefined', (context) => {
  assert.strictEqual(context.student.getName(), '');
});
