const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");

    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0, "First student should have ID 0");

    const id2 = myClass.addStudent(new Student());
    assert.strictEqual(id2, 1, "Second student should have ID 1");

    const invalidId = myClass.addStudent({});
    assert.strictEqual(invalidId, -1, "Adding non-Student instance should return -1");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Jane");
    myClass.addStudent(student);

    assert.strictEqual(myClass.getStudentById(0).getName(), "Jane", "Student with ID 0 should be Jane");
    assert.strictEqual(myClass.getStudentById(1), null, "Fetching non-existent student should return null");
    assert.strictEqual(myClass.getStudentById(-1), null, "Fetching with negative ID should return null");
});

test("Test Student's setName", () => {
    const student = new Student();
    student.setName("Doe");
    assert.strictEqual(student.getName(), "Doe", "Student name should be Doe");

    student.setName(123);
    assert.strictEqual(student.getName(), "Doe", "Student name should remain Doe if setName is called with non-string");
});

test("Test Student's getName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), "", "Default student name should be empty string");

    student.setName("Smith");
    assert.strictEqual(student.getName(), "Smith", "Student name should be Smith after setting it");
});