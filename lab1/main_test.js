const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();

    const student1 = new Student();
    student1.setName("Alice");
    const id1 = myClass.addStudent(student1);
    assert.strictEqual(id1, 0, "First student should have ID 0");

    const student2 = new Student();
    student2.setName("Bob");
    const id2 = myClass.addStudent(student2);
    assert.strictEqual(id2, 1, "Second student should have ID 1");

    const invalidStudent = { name: "Charlie" }; // Not an instance of Student
    const invalidId = myClass.addStudent(invalidStudent);
    assert.strictEqual(invalidId, -1, "Should return -1 when adding an invalid student");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();

    const student1 = new Student();
    student1.setName("Alice");
    myClass.addStudent(student1);

    const student2 = new Student();
    student2.setName("Bob");
    myClass.addStudent(student2);

    assert.strictEqual(myClass.getStudentById(0).getName(), "Alice", "Should return student Alice");
    assert.strictEqual(myClass.getStudentById(1).getName(), "Bob", "Should return student Bob");
    assert.strictEqual(myClass.getStudentById(2), null, "Invalid ID should return null");
    assert.strictEqual(myClass.getStudentById(-1), null, "Negative ID should return null");
});

test("Test Student's setName", () => {
    const student = new Student();

    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice", "Should set name to 'Alice'");

    student.setName(123); // Invalid type
    assert.strictEqual(student.getName(), "Alice", "Invalid input should not change the name");
});

test("Test Student's getName", () => {
    const student = new Student();

    assert.strictEqual(student.getName(), "", "Default name should be an empty string");

    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice", "Should return 'Alice' after setting name");

});
