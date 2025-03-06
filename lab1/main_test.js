const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();

    const studentId = myClass.addStudent(student);
    // const name = ['John'];
    assert.strictEqual(studentId, 0);

    assert.strictEqual(myClass.addStudent({}), -1);
    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();
    const student = new Student();
    student.setName("John");
    const studentId = myClass.addStudent(student);
    
    const retrievedStudent = myClass.getStudentById(studentId);
    assert.strictEqual(retrievedStudent, student);
    
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(100), null);
    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();
    
    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice");
    
    student.setName(123);
    assert.strictEqual(student.getName(), "Alice"); 
    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();
    
    assert.strictEqual(student.getName(), "");
    
    student.setName("Bob");
    assert.strictEqual(student.getName(), "Bob");
    // throw new Error("Test not implemented");
});