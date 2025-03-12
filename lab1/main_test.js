const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();

    const student = new Student();
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0);
    assert.strictEqual(myClass.addStudent({}), -1);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    student.setName("Name");
    assert.strictEqual(myClass.getStudentById(-1), null);

    const id = myClass.addStudent(student);

    const student_return = myClass.getStudentById(id);
    assert.strictEqual(student_return.getName(), "Name");
    assert.strictEqual(myClass.getStudentById(10000), null);
});


test("Test Student's setName", () => {
    const student = new Student();
    student.setName(123); // input is not a string object
    assert.strictEqual(student.getName(), '');

    student.setName("name1");
    assert.strictEqual(student.getName(), "name1");

});

test("Test Student's getName", () => {
    const student = new Student();

    assert.strictEqual(student.getName(), "");

    student.setName("name1");
    assert.strictEqual(student.getName(), "name1");
});
