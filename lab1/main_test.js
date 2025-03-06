const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const student = new Student();
    const myClass = new MyClass();
    assert.strictEqual(myClass.addStudent(100), -1);
    assert.strictEqual(myClass.addStudent(student), 0);
});

test("Test MyClass's getStudentById", () => {
    const student = new Student();
    const myClass = new MyClass();
    const id = myClass.addStudent(student);
    assert.strictEqual(myClass.getStudentById(100), null);
    assert.strictEqual(myClass.getStudentById(id), student);
});

test("Test Student's setName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), '');
    student.setName(100);
    assert.strictEqual(student.getName(), '');
    student.setName('Alice');
    assert.strictEqual(student.getName(), 'Alice');
});

test("Test Student's getName", () => {
    const student = new Student();
    student.setName('Alice');
    assert.strictEqual(student.getName(), 'Alice');
});
