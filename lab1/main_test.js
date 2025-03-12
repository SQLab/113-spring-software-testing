const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const Class = new MyClass();
    const student = new Student();
    const id = Class.addStudent(student);
    assert.strictEqual(id, 0);
    assert.strictEqual(Class.addStudent({}), -1);
});

test("Test MyClass's getStudentById", () => {
    const Class =  new MyClass();
    const student = new Student();
    student.setName("John");

    const id = Class.addStudent(student);
    const StudentID = Class.getStudentById(id);

    assert.strictEqual(StudentID.getName(), "John");
    assert.strictEqual(Class.getStudentById(-1), null); 
    assert.strictEqual(Class.getStudentById(999), null);

});

test("Test Student's setName", () => {
    const student = new Student();
    student.setName(123);  
    assert.strictEqual(student.getName(), "");

    student.setName("John");
    const StudentName = student.getName();

    
    assert.strictEqual(StudentName, "John");
    
});

test("Test Student's getName", () => {
    const student = new Student();

    // "" in default
    assert.strictEqual(student.getName(), "");
    
    student.setName("John");
    const StudentName = student.getName();
    assert.strictEqual(StudentName, "John");
});