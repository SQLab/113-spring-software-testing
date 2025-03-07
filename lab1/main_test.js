const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');



test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();

    const student_0 = 123;
    assert.strictEqual(myClass.addStudent(student_0), -1);

    const student_1 = new Student();
    student_1.setName('John');
    assert.strictEqual(myClass.addStudent(student_1), 0);
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();

    assert.strictEqual(myClass.getStudentById(99), null);

    const student_1 = new Student();
    student_1.setName("John");
    const studentID_1 = myClass.addStudent(student_1);
    const retrievedStudent_1 = myClass.getStudentById(studentID_1);
    assert.ok(retrievedStudent_1 instanceof Student, "Should return a Student object");
    assert.strictEqual(myClass.getStudentById(studentID_1).getName(), "John");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();
    student.setName("John")
    assert.strictEqual(student.getName(), "John");

    student.setName(123);
    assert.strictEqual(student.getName(), 'John');
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();

    assert.strictEqual(student.getName(), '');

    student.setName("John");
    assert.strictEqual(student.getName(), "John");

    student.setName(123);
    assert.strictEqual(student.getName(), "John");
});
