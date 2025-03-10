const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();

    const invalidResult = myClass.addStudent({});
    assert.strictEqual(invalidResult, -1);

    const student = new Student();
    student.setName('Alice');
    const index = myClass.addStudent(student);
    assert.strictEqual(index, 0);

    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();

    const invalidResult1 = myClass.getStudentById(-1);
    assert.strictEqual(invalidResult1, null);

    const invalidResult2 = myClass.getStudentById(100);
    assert.strictEqual(invalidResult2, null);

    const student = new Student();
    student.setName('Alice');
    myClass.addStudent(student);
    const index = myClass.getStudentById(0);
    assert.strictEqual(index, student);

    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student1 = new Student();
    student1.setName(0);
    assert.strictEqual(student1.getName(), "");

    const student2 = new Student();
    student2.setName('Alice');
    assert.strictEqual(student2.getName("Alice"), "Alice");

    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student1 = new Student();
    assert.strictEqual(student1.getName(), "");

    const student2 = new Student();
    student2.setName('Alice');
    assert.strictEqual(student2.getName(), "Alice");

    // throw new Error("Test not implemented");
});