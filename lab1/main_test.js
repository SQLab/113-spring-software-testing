const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    const studentId = myClass.addStudent(student);
    
    assert.strictEqual(studentId, 0, "Student ID should be 0 for the first student");
    assert.strictEqual(myClass.students.length, 1, "Student list should have 1 student");
    
    // Test adding an invalid student
    const invalidStudentId = myClass.addStudent({});
    assert.strictEqual(invalidStudentId, -1, "Invalid student should return -1");
    //throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    myClass.addStudent(student);
    
    assert.strictEqual(myClass.getStudentById(0), student, "Should return the correct student");
    assert.strictEqual(myClass.getStudentById(1), null, "Should return null for out-of-bounds ID");
    assert.strictEqual(myClass.getStudentById(-1), null, "Should return null for negative ID");
    //throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    const student = new Student();
    student.setName("stellaglow1122");
    assert.strictEqual(student.name, "stellaglow1122", "Student name should be set correctly");
    
    student.setName(123);
    assert.strictEqual(student.name, "stellaglow1122", "Student name should not change when given a non-string");
    //throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), "", "getName should return an empty string if name is undefined");
    
    student.setName("stellaglow1122");
    assert.strictEqual(student.getName(), "stellaglow1122", "getName should return the correct name");
    //throw new Error("Test not implemented");
});