const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0);
    assert.strictEqual(myClass.getStudentById(id), student);
    
    assert.strictEqual(myClass.addStudent({}), -1);
    assert.strictEqual(myClass.addStudent(null), -1);
    assert.strictEqual(myClass.addStudent(777), -1);
    assert.strictEqual(myClass.addStudent("string"), -1);
    //throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    const student2 = new Student();
    
    myClass.addStudent(student1);
    myClass.addStudent(student2);
    
    assert.strictEqual(myClass.getStudentById(0), student1);
    assert.strictEqual(myClass.getStudentById(1), student2);
    
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(2), null);
    assert.strictEqual(myClass.getStudentById(1000), null);
    //throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    const student = new Student();
    
    student.setName("Max");
    assert.strictEqual(student.getName(), "Max");
    
    student.setName(123);
    assert.strictEqual(student.getName(), "Max");
    
    student.setName(null);
    assert.strictEqual(student.getName(), "Max");
    
    student.setName(undefined);
    assert.strictEqual(student.getName(), "Max");
    //throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    const student = new Student();
    
    assert.strictEqual(student.getName(), "");
    
    student.setName("JHH");
    assert.strictEqual(student.getName(), "JHH");
    //throw new Error("Test not implemented");
});