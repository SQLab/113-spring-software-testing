const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

// Test MyClass's addStudent method
test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName('John');
    
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0); // Should return 0 as this is the first student added
    
    const invalidStudent = {};
    const invalidId = myClass.addStudent(invalidStudent);
    assert.strictEqual(invalidId, -1); // Invalid student should return -1
});

// Test MyClass's getStudentById method
test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName('Jane');
    
    myClass.addStudent(student);
    const retrievedStudent = myClass.getStudentById(0);
    assert.strictEqual(retrievedStudent.getName(), 'Jane'); // Should retrieve student 'Jane'
    
    const nonExistentStudent = myClass.getStudentById(1);
    assert.strictEqual(nonExistentStudent, null); // Should return null for invalid index
});

// Test Student's setName method
test("Test Student's setName", () => {
    const student = new Student();
    student.setName('Alice');
    assert.strictEqual(student.getName(), 'Alice'); // Should return 'Alice'
    
    student.setName(123); // Invalid name
    assert.strictEqual(student.getName(), 'Alice'); // Should not change name if invalid input
});

// Test Student's getName method
test("Test Student's getName", () => {
    const student = new Student();
    assert.strictEqual(student.getName(), ''); // Should return empty string if name is undefined
    
    student.setName('Bob');
    assert.strictEqual(student.getName(), 'Bob'); // Should return 'Bob' after setting the name
});
