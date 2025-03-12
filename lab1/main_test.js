const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    
    assert.strictEqual(myClass.addStudent(student), 0);
    assert.strictEqual(myClass.addStudent(new Student()), 1);

    assert.strictEqual(myClass.addStudent({}), -1);
    assert.strictEqual(myClass.addStudent(null), -1);
    assert.strictEqual(myClass.addStudent(123), -1);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();

    student.setName("Cool Name");
    const studentId = myClass.addStudent(student);

    assert.strictEqual(myClass.getStudentById(studentId), student);

    assert.strictEqual(myClass.getStudentById(100), null);
    assert.strictEqual(myClass.getStudentById(-1), null);
});

test("Test Student's setName", () => {
    const student = new Student();

    student.setName("Cool Name");
    assert.strictEqual(student.getName(), "Cool Name");

    student.setName(null);
    assert.strictEqual(student.getName(), "Cool Name");

    student.setName(123);
    assert.strictEqual(student.getName(), "Cool Name");

    student.setName(undefined);
    assert.strictEqual(student.getName(), "Cool Name");
});

test("Test Student's getName", () => {
    const student = new Student();
    
    assert.strictEqual(student.getName(), "");

    student.setName("Cool Name");
    assert.strictEqual(student.getName(), "Cool Name");
});