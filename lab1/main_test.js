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

    const newStudentId2 = myClass.addStudent('not a student');
    assert.strictEqual(newStudentId2, -1);

    // throw new Error("Test not implemented");

});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    myClass.addStudent(student);
    const studentById = myClass.getStudentById(0);
    assert.strictEqual(studentById, student);

    const studentById2 = myClass.getStudentById(-1);
    assert.strictEqual(studentById2, null);
    const studentById3 = myClass.getStudentById(1);
    assert.strictEqual(studentById3, null);

    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();
    student.setName("John");
    assert.strictEqual(student.getName(), "John");

    const student2 = new Student();
    student2.setName(123);
    assert.strictEqual(student.getName(), "John");

    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();
    student.setName("John");
    assert.strictEqual(student.getName(), "John");

    const student2 = new Student();
    student2.setName(123);
    assert.strictEqual(student2.getName(), '');

    // throw new Error("Test not implemented");
});