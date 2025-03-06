const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');
const exp = require('constants');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    const newStudentId = myClass.addStudent(student);
    assert.strictEqual(newStudentId, 0);
    assert.strictEqual(myClass.students.length, 1);
    assert.strictEqual(myClass.students[0], student);

    // throw new Error("Test not implemented");

});

test("Test MyClass's getStudentById", () => {
    // TODO
    throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    throw new Error("Test not implemented");
});