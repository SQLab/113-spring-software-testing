const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    
    const student1 = new Student();
    student1.setName("Alice");
    const id1 = myClass.addStudent(student1);
    assert.strictEqual(id1, 0, "First student ID should be 0");

    const student2 = new Student();
    student2.setName("Bob");
    const id2 = myClass.addStudent(student2);
    assert.strictEqual(id2, 1, "Second student ID should be 1");

    const invalidId = myClass.addStudent({ name: "FakeStudent" });
    assert.strictEqual(invalidId, -1, "Non-Student object should return -1");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Charlie");
    
    const id = myClass.addStudent(student);
    const retrievedStudent = myClass.getStudentById(id);
    assert.ok(retrievedStudent, "Student should be retrieved");
    assert.strictEqual(retrievedStudent.getName(), "Charlie", "Retrieved student's name should match");

    assert.strictEqual(myClass.getStudentById(-1), null, "Negative ID should return null");
    assert.strictEqual(myClass.getStudentById(99), null, "Out of range ID should return null");
});

test("Test Student's setName", () => {
    const student = new Student();

    student.setName("David");
    assert.strictEqual(student.getName(), "David", "Should set name correctly");

    student.setName(12345);
    assert.strictEqual(student.getName(), "David", "Non-string name should be ignored");

    student.setName("");
    assert.strictEqual(student.getName(), "", "Empty string should be a valid name");
});

test("Test Student's getName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), "", "Default name should be empty string");

    student.setName("Eve");
    assert.strictEqual(student.getName(), "Eve", "getName should return the correct name");
});