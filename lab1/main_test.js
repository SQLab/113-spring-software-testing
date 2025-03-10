const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student("Aker");
    const student_same = new Student("Aker");
    const student_invalid = "Aker";
    // Check if invalid student is not added to the classroom
    assert.strictEqual(myClass.addStudent(student_invalid), -1);
    const id = myClass.addStudent(student);
    // Check if first student is added to the classroom
    assert.strictEqual(id, 0);
    assert.strictEqual(myClass.students.length, 1);
    const id_same = myClass.addStudent(student_same);
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student = new Student("Aker");
    const id = myClass.addStudent(student);
    // Check if the student is retrieved by id
    assert.strictEqual(myClass.getStudentById(id), student);
    assert.strictEqual(myClass.getStudentById(-1), null);
    assert.strictEqual(myClass.getStudentById(1), null);
});

test("Test Student's setName", () => {
    const student = new Student("Aker");
    student.setName(123);
    assert.strictEqual(student.name, undefined);
    student.setName(null);
    assert.strictEqual(student.name, undefined);
    student.setName("");
    assert.strictEqual(student.name, "");
    student.setName("Aker");
    assert.strictEqual(student.name, "Aker");    
});

test("Test Student's getName", () => {
    const student = new Student("Aker");
    student.setName(undefined);
    assert.strictEqual(student.getName(), "");
    student.setName("Aker");
    assert.strictEqual(student.getName(), "Aker");
});