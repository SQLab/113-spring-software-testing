const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName('John');

    // [valid] Add student to myClass
    const newStudentId = myClass.addStudent(student);
    assert.strictEqual(newStudentId, 0, 'Add student to myClass should return 0');

    // [invalid] Add Invalid Student
    const invalidId = myClass.addStudent({name: 'Invalid'});
    assert.strictEqual(invalidId, -1, 'Add invalid student should return -1');
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName('Jane');
    
    const id = myClass.addStudent(student);
    
    // [valid] Get student by valid ID
    const retrievedStudent = myClass.getStudentById(id);
    assert.strictEqual(retrievedStudent.getName(), 'Jane');
    
    // [invalid] Get student by invalid ID
    assert.strictEqual(myClass.getStudentById(-1), null, 'Get student by invalid ID should return null');
    assert.strictEqual(myClass.getStudentById(999), null, 'Get student by invalid ID should return null');
});

test("Test Student's setName", () => {
    const student = new Student();
    
    // [valid] Set valid name
    student.setName('David');
    assert.strictEqual(student.getName(), 'David', 'Set valid name should return David');
    
    // [invalid] Set non-string name
    student.setName(123);
    assert.strictEqual(student.getName(), 'David', 'Set non-string name should return David');
});

test("Test Student's getName", () => {
    const student = new Student();
    
    // [valid] Get name after getName
    assert.strictEqual(student.getName(), '', 'Get name should return empty string');
    
    // [valid] Set name after getName
    student.setName('Smith');
    assert.strictEqual(student.getName(), 'Smith', 'Set name should return Smith');
});