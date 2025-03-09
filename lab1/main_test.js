const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    assert.strictEqual(1, 1);
    const myclass = new MyClass();
    const student = new Student();
    assert.strictEqual(myclass.addStudent(student), 0);
    assert.strictEqual(myclass.addStudent(1), -1);      // not a student
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myclass = new MyClass();
    const student = new Student();
    const id = myclass.addStudent(student);
    assert.strictEqual(myclass.getStudentById(-1), null);
    assert.strictEqual(myclass.getStudentById(1), null);
    assert.strictEqual(myclass.getStudentById(id), student);
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();
    student.setName("hello");
    student.setName(1);
    assert.strictEqual(student.getName(), "hello");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();
    assert.strictEqual(student.getName(), "");
    student.setName("hello");
    assert.strictEqual(student.getName(), "hello");
});