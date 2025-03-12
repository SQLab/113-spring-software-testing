const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Jessica");
    
    const studentId = myClass.addStudent(student);
    assert.strictEqual(studentId, 0, "Student should be added at index 0");
    
    const invalidStudentId = myClass.addStudent({ name: "Jessie" });
    assert.strictEqual(invalidStudentId, -1, "Invalid student should return -1");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Jessica");
    myClass.addStudent(student);
    
    const expectedStudent = myClass.getStudentById(0);
    assert.strictEqual(expectedStudent.getName(), "Jessica", "Student name should be Jessica");
    
    const invalidStudent = myClass.getStudentById(1);
    assert.strictEqual(invalidStudent, null, "Invalid ID should return null");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();

    student.setName("Jessica");
    assert.strictEqual(student.getName(), "Jessica", "Student name should be Jessica");

    student.setName(123);
    assert.strictEqual(student.getName(), "Jessica", "Name should not change when setting an invalid type");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();

    assert.strictEqual(student.getName(), "", "Student name have not been set yet");

    student.setName("Jessica");
    assert.strictEqual(student.getName(), "Jessica", "Student name should be Jessica");
});