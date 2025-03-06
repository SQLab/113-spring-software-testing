const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    // throw new Error("Test not implemented");
    const myClass = new MyClass();
    let numOfStudent = myClass.addStudent(null);
    assert.strictEqual(numOfStudent, -1);
    const student = new Student();
    numOfStudent = myClass.addStudent(student);
    assert.strictEqual(numOfStudent, 0);
});

test("Test MyClass's getStudentById", () => {
    // TODO
    // throw new Error("Test not implemented");
    const myClass = new MyClass();
    let studentById = myClass.getStudentById(0);
    assert.strictEqual(studentById, null);
    const student = new Student();
    myClass.addStudent(student);
    studentById = myClass.getStudentById(0);
    assert.strictEqual(studentById, student);
    studentById = myClass.getStudentById(1);
    assert.strictEqual(studentById, null);
});

test("Test Student's setName", () => {
    // TODO
    // throw new Error("Test not implemented");
    const student = new Student();
    student.setName(123);
    assert.strictEqual(student.getName(), '');
    student.setName('John');
    assert.strictEqual(student.getName(), 'John');
});

test("Test Student's getName", () => {
    // TODO
    // throw new Error("Test not implemented");
    const student = new Student();
    assert.strictEqual(student.getName(), '');
    student.setName('John');
    assert.strictEqual(student.getName(), 'John');
});