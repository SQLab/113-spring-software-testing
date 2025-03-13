const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");

    // Test adding a valid student
    const newStudentId = myClass.addStudent(student);
    assert.strictEqual(newStudentId, 0, "Expected student ID to be 0");

    // Test adding an invalid student (not an instance of Student)
    const invalidStudent = {};
    const result = myClass.addStudent(invalidStudent);
    assert.strictEqual(result, -1, "Expected result to be -1 for invalid student");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName("John");
    myClass.addStudent(student1);

    // Test getting an existing student by ID
    const retrievedStudent = myClass.getStudentById(0);
    assert.strictEqual(retrievedStudent.getName(), "John", "Expected student name to be John");

    // Test getting a non-existing student by ID
    const nonExistingStudent = myClass.getStudentById(1);
    assert.strictEqual(nonExistingStudent, null, "Expected null for non-existing student");
});

test("Test Student's setName", () => {
    const student = new Student();

    // Test setting valid name
    student.setName("Jane");
    assert.strictEqual(student.getName(), "Jane", "Expected student name to be Jane");

    // Test setting invalid name (not a string)
    student.setName(123);
    assert.strictEqual(student.getName(), "Jane", "Expected student name to remain Jane");

    // Test setting undefined name
    student.setName(undefined);
    assert.strictEqual(student.getName(), "Jane", "Expected student name to remain Jane");
});

test("Test Student's getName", () => {
    const student = new Student();
    student.setName("Doe");

    // Test getting name after setting it
    assert.strictEqual(student.getName(), "Doe", "Expected student name to be Doe");

    // Test getting name when name is undefined
    const student2 = new Student();
    assert.strictEqual(student2.getName(), "", "Expected student name to be empty string");
});
