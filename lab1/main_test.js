const assert = require('assert');
const { MyClass, Student } = require('./main');


test("Test MyClass's addStudent", () => {
    // TODO
    throw new Error("Test not implemented");
    const name = 'John'
    const myClass = new MyClass();
    assert.strictEqual(myClass.addStudent(name), -1);
    const student = new Student();
    student.setName(name[0]);
    assert.strictEqual(myClass.addStudent(student), 0);
});

test("Test MyClass's getStudentById", () => {
    // TODO
    throw new Error("Test not implemented");
    const name = 'John'
    const myClass = new MyClass();
    const student = new Student();
    student.setName(name);
    const studentId = myClass.addStudent(student);
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(2), null);
    assert.strictEqual(myClass.getStudentById(studentId).name, student.name);
});

test("Test Student's setName", () => {
    // TODO
    throw new Error("Test not implemented");
    const num = 10;
    const name = 'John'
    const student = new Student();
    student.setName(num);
    assert.strictEqual(student.name, undefined);
    student.setName(name);
    assert.strictEqual(student.name, name);

});

test("Test Student's getName", () => {
    // TODO
    throw new Error("Test not implemented");
    const name = 'John'
    const student = new Student();
    assert.strictEqual(student.getName(), '');
    student.setName(name);
    assert.strictEqual(student.getName(), name);
});