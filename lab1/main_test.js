const test = require('node:test');
const assert = require('assert');
const { MyClass, Student} = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass()
    const student = new Student()

    const newStudentId = myClass.addStudent(student);

    assert.strictEqual(newStudentId, 0);
    assert.strictEqual(myClass.addStudent({}), -1);

    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");

    const studentId = myClass.addStudent(student);

    const foundStudent = myClass.getStudentById(studentId);
    assert.strictEqual(foundStudent, student);

    assert.strictEqual(myClass.getStudentById(-5), null)
    assert.strictEqual(myClass.getStudentById(123), null)
    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();

    student.setName("Mike");
    assert.strictEqual(student.getName(), "Mike");

    student.setName(222);
    assert.strictEqual(student.getName(), "Mike");
    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();

    assert.strictEqual(student.getName(), "");

    student.setName("John");
    assert.strictEqual(student.getName(), "John");
    // throw new Error("Test not implemented");
});