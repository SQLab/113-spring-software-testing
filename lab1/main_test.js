const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    
    // Valid student case
    const studentId = myClass.addStudent(student);
    assert.strictEqual(studentId, 0);

    // Invalid input case
    const invalidId = myClass.addStudent({});
    assert.strictEqual(invalidId, -1);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");
    
    const studentId = myClass.addStudent(student);
    
    // Valid retrieval
    const retrievedStudent = myClass.getStudentById(studentId);
    assert.ok(retrievedStudent instanceof Student);
    assert.strictEqual(retrievedStudent.getName(), "John");

    // Invalid ID cases
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(101), null);
});


test("Test Student's setName", () => {
    const student = new Student();
    
    // Valid name setting
    student.setName("Jane");
    assert.strictEqual(student.getName(), "Jane");

    // Invalid input cases
    student.setName(123);
    assert.strictEqual(student.getName(), "Jane");  // Should not change

    student.setName(null);
    assert.strictEqual(student.getName(), "Jane");  // Should not change
});

test("Test Student's getName", () => {
    const student = new Student();
    
    // Default value case
    assert.strictEqual(student.getName(), '');

    // After setting a valid name
    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice");
});
