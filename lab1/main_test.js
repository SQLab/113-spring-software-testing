const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

const myclass = new MyClass;

test("Test MyClass's addStudent", () => {
    // TODO
    assert.equal(-1, myclass.addStudent('Oops'));
    const student = new Student;
    const name = 'Kiwi'
    student.setName(name);
    assert.equal(0, myclass.addStudent(student));
    return;
    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    assert.equal(null, myclass.getStudentById(-3));
    assert.equal(null, myclass.getStudentById(10));
    const student = new Student;
    const name = 'Kiwi'
    student.setName(name);
    const id = myclass.addStudent(student);
    assert.equal(student, myclass.getStudentById(id));
    return;
    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student;
    student.setName(123);
    assert.equal(undefined, student.name);

    const name = 'Kiwi'
    student.setName(name);
    assert.equal(name, student.name);
    return;
    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student;
    assert.equal('', student.getName());
    const name = 'Kiwi'
    student.setName(name);
    assert.equal(name, student.getName());
    return;
    // throw new Error("Test not implemented");
});