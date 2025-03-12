const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');


test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();

    student.setName('Sam');
    const studentID = myClass.addStudent(student);
    const nonStudent = { name: "Bob", age: 25 };
    const nonStudentID = myClass.addStudent(nonStudent);

    assert.strictEqual(studentID, 0);
    assert.strictEqual(nonStudentID, -1);


});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student();
    const student2 = new Student();


    student.setName('Sam');
    myClass.addStudent(student)
    myClass.addStudent(student2)
    const studentID = myClass.addStudent(student);
    const student2ID = myClass.addStudent(student2);


    assert.strictEqual(myClass.getStudentById(0), student);
    assert.strictEqual(myClass.getStudentById(student2ID), student2);
    assert.strictEqual(myClass.getStudentById(4), null);




});

test("Test Student's setName", () => {
    const myClass = new MyClass();
    const student = new Student();
    const student1 = new Student();


    const studentID = myClass.addStudent(student);
    const student1ID = myClass.addStudent(student);

    student.setName('Sam');
    student1.setName(10);

    assert.strictEqual(student.getName(), 'Sam');
    assert.strictEqual(student.name, 'Sam');
    assert.strictEqual(myClass.getStudentById(studentID).name, 'Sam');
    assert.strictEqual(student1.name, undefined);



});

test("Test Student's getName", () => {
    const myClass = new MyClass();
    const student = new Student();
    const student1 = new Student();


    student.setName('Sam');

    assert.strictEqual(student.getName(), 'Sam')
    assert.strictEqual(student1.getName(), '')



});