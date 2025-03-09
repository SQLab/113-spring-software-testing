const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    
    // Test valid student addition
    const student = new Student();
    const studentId = myClass.addStudent(student);
    assert.strictEqual(studentId, 0);
    
    // Test adding another valid student
    const anotherStudent = new Student();
    const anotherId = myClass.addStudent(anotherStudent);
    assert.strictEqual(anotherId, 1);
    
    // Test adding invalid student (not a Student instance)
    const invalidStudentId = myClass.addStudent({});
    assert.strictEqual(invalidStudentId, -1);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("TestName");
    const studentId = myClass.addStudent(student);
    
    // Test getting a valid student
    const retrievedStudent = myClass.getStudentById(studentId);
    assert.strictEqual(retrievedStudent, student);
    
    // Test with invalid ID (negative)
    const invalidStudent1 = myClass.getStudentById(-1);
    assert.strictEqual(invalidStudent1, null);
    
    // Test with invalid ID (out of bounds)
    const invalidStudent2 = myClass.getStudentById(999);
    assert.strictEqual(invalidStudent2, null);
});

test("Test Student's setName", () => {
    const student = new Student();
    
    // Test with valid name
    student.setName("TestName");
    assert.strictEqual(student.name, "TestName");
    
    // Test with invalid name (non-string)
    student.setName(123);
    assert.strictEqual(student.name, "TestName"); // Name shouldn't change
    
    // Test with invalid name (null)
    student.setName(null);
    assert.strictEqual(student.name, "TestName"); // Name shouldn't change
});

test("Test Student's getName", () => {
    const student = new Student();
    
    // Test with undefined name (initial state)
    assert.strictEqual(student.getName(), '');
    
    // Test with set name
    student.setName("TestName");
    assert.strictEqual(student.getName(), "TestName");
});
