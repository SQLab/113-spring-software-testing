const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass\'s addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0); 
    
    const invalidId = myClass.addStudent("invalid student");
    assert.strictEqual(invalidId, -1); 
});

test("Test MyClass\'s getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Ann");
    
    const id = myClass.addStudent(student);
    const retrievedStudent = myClass.getStudentById(id);
    
    assert.ok(retrievedStudent instanceof Student); 
    assert.strictEqual(retrievedStudent.getName(), "Ann");
    
    assert.strictEqual(myClass.getStudentById(-1), null); 
    assert.strictEqual(myClass.getStudentById(100), null);
});

test("Test Student's setName", () => {
    const student = new Student();
    
    student.setName("Anton");
    assert.strictEqual(student.getName(), "Anton");

    student.setName(1);
    assert.strictEqual(student.getName(), "Anton");

    student.setName(null);
    assert.strictEqual(student.getName(), "Anton");

    student.setName(undefined);
    assert.strictEqual(student.getName(), "Anton");
});

test("Test Student's getName", () => {
    const student = new Student();
    
    assert.strictEqual(student.getName(), "");
    
    student.setName("Cheri");
    assert.strictEqual(student.getName(), "Cheri");
});