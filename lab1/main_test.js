const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName("Alice");

    const studentId = myClass.addStudent(student1);
    assert.strictEqual(studentId, 0, "First student ID should be 0");


    const invalidStudent = myClass.addStudent({});
    assert.strictEqual(invalidStudent, -1, "Adding a non-Student object should return -1");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName("Alice");
    myClass.addStudent(student1);

    assert.strictEqual(myClass.getStudentById(0).getName(), "Alice", "Should return Alice");
    assert.strictEqual(myClass.getStudentById(2), null, "ID out of range should return null");
});

test("Test Student's setName", () => {
    const student = new Student();
    
    student.setName("Bob");
    assert.strictEqual(student.getName(), "Bob", "Name should be Bob");

    student.setName(12345);
    assert.strictEqual(student.getName(), "Bob", "Setting name to non-string should not change it");
});

test("Test Student's getName", () => {
    const student = new Student();
    
    assert.strictEqual(student.getName(), "", "Default name should be an empty string");

    student.setName("David");
    assert.strictEqual(student.getName(), "David", "getName() should return 'David'");
});
