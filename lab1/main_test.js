const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();

    // Check handling of invalid input
    assert.strictEqual(myClass.addStudent("not a Student"), -1);

    // Sanity check: no students should be added
    assert.strictEqual(myClass.students.length, 0);

    // Insert a valid student
    const student = new Student();
    const studentId = myClass.addStudent(student);
    assert.strictEqual(studentId, 0);

    // Validate that the student was added
    assert.strictEqual(myClass.students.length, 1);
    assert.strictEqual(myClass.students[studentId], student);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();

    // Check handling of invalid input (out of bounds id)
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(0), null);

    // Insert a valid student
    const student = new Student();
    const studentId = myClass.addStudent(student);

    // Check that the student can be retrieved by id
    assert.strictEqual(myClass.getStudentById(studentId), student);
});

test("Test Student's setName", () => {
    const student = new Student();

    // Check handling of invalid input
    student.setName(42);
    assert.strictEqual(student.name, undefined);

    // Set a valid name
    student.setName("John Doe");

    // Check that the name was set correctly
    assert.strictEqual(student.name, "John Doe");
});

test("Test Student's getName", () => {
    const student = new Student();

    // Check that the name is empty when not set
    assert.strictEqual(student.getName(), '');

    // Set a name and check that it is returned correctly
    const name = "John Doe";
    student.setName(name);
    assert.strictEqual(student.getName(), name);
});