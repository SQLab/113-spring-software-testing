const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();

    const student = new Student();
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0);
    assert.strictEqual(Class.addStudent({}), -1);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(0), null);
    assert.strictEqual(myClass.getStudentById(1), null);

    const student = new Student();
    student.setName("Name");
    const id = myClass.addStudent(student);

    const student_return = myClass.getStudentById(id);
    assert.ok(student_return instanceof Student);
    assert.strictEqual(student_return.getName(), "Name");
    assert.strictEqual(myClass.getStudentById(10000), null);
});


test("Test Student's setName", () => {
    const student = new Student();
    student.setName(123); // input is not a string object
    assert.strictEqual(student.getName(), '');

    student.setName("name1");
    assert.strictEqual(student.getName(), "name1");

    student.setName(123);
    assert.strictEqual(student.getName(), "name1");

    student.setName("change name");
    assert.strictEqual(student.getName(), "change name");

});

test("Test Student's getName", () => {
    const student = new Student();

    assert.strictEqual(student.getName(), "");

    student.setName("name1");
    assert.strictEqual(student.getName(), "name1");
});
