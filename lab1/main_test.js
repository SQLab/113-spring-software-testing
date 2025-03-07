const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");

    const index = myClass.addStudent(student);
    assert.strictEqual(index, 0, "First student should be at index 0");

    const invalidStudent = {};
    const invalidIndex = myClass.addStudent(invalidStudent);
    assert.strictEqual(invalidIndex, -1, "Invalid student should return -1");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName("John");
    myClass.addStudent(student1);

    const student2 = new Student();
    student2.setName("Jane");
    myClass.addStudent(student2);

    const retrievedStudent1 = myClass.getStudentById(0);
    assert.strictEqual(retrievedStudent1.getName(), "John", "Should retrieve 'Bob'");

    const retrievedStudent2 = myClass.getStudentById(1);
    assert.strictEqual(retrievedStudent2.getName(), "Jane", "Should retrieve 'Charlie'");

    const nonExistent = myClass.getStudentById(999);
    assert.strictEqual(nonExistent, null, "Non-existent ID should return null");
});

test("Test Student's setName", () => {
    const student = new Student();
    student.setName("Dave");
    assert.strictEqual(student.getName(), "Dave", "Name should be 'Dave'");

    student.setName(123);
    assert.strictEqual(student.getName(), "Dave", "Name should remain 'Dave' after invalid set attempt");
});

test("Test Student's getName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), '', "Initial name should be empty string");

    student.setName("Eve");
    assert.strictEqual(student.getName(), "Eve", "Name should be 'Eve'");
});