const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();

    const invalidResult = myClass.addStudent({});
    assert.strictEqual(invalidResult, -1);

    student.setName('Alice');
    const index = myClass.addStudent(student);
    assert.strictEqual(index, 0);

});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();

    assert.strictEqual(myClass.getStudentById(0), null);
    assert.strictEqual(myClass.getStudentById(100), null);

    student.setName('Alice');
    myClass.addStudent(student);
    const validStudent = myClass.getStudentById(0);
    assert.strictEqual(validStudent.getName(), 'Alice');
});

test("Test Student's setName", () => {
    const student = new Student();

    student.setName(0);
    assert.strictEqual(student.getName(), '');

    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice");
});

test("Test Student's getName", () => {
    const student = new Student();

    assert.strictEqual(student.getName(), '');

    student.setName("Alice");
    assert.strictEqual(student.getName(), "Alice");
});