const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const testClass = new MyClass();
    const testStudent = new Student();
    const testStudentId = testClass.addStudent(testStudent);
    assert.strictEqual(testStudentId, 0, 'First student should have ID 0');

    const invalidId = testClass.addStudent({ name: "Not a Student" });
    assert.strictEqual(invalidId, -1, 'Should return -1 for non-Student objects');
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const testClass = new MyClass();
    const testStudent = new Student();
    testStudent.setName('Bob')
    const testStudentId = testClass.addStudent(testStudent)

    const testStudent_1 = testClass.getStudentById(testStudentId);
    assert.strictEqual(testStudent_1.getName(), 'Bob', 'Should retrieve the correct student');

    assert.strictEqual(testClass.getStudentById(-1), null, 'Should return null for negative ID');

    assert.strictEqual(testClass.getStudentById(100), null, 'Should return null for out-of-bounds ID');
});

test("Test Student's setName", () => {
    // TODO
    const testStudent = new Student();
    testStudent.setName(1);
    assert.strictEqual(testStudent.getName(), '', "Should return empty for error type")
    
    testStudent.setName('Bob');
    assert.strictEqual(testStudent.getName(), 'Bob', 'Should set the same name with setName');
});

test("Test Student's getName", () => {
    // TODO
    const testStudent = new Student();
    assert.strictEqual(testStudent.getName(), '', 'Should return empty before setName')
    testStudent.setName('Bob');
    assert.strictEqual(testStudent.getName(), 'Bob', 'Should return same name after setName')
});