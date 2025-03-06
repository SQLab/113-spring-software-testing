const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();

    const student1 = new Student();
    student1.setName('John');
    const studentId = myClass.addStudent(student1);
    assert.strictEqual(studentId, 0, "The first student ID should be 0");

    const student2 = new Student();
    student2.setName('Jane');
    const studentId2 = myClass.addStudent(student2);
    assert.strictEqual(studentId2, 1, "The second student ID should be 1");

    const invalidId = myClass.addStudent({ name: 'Invalid' });
    assert.strictEqual(invalidId, -1, "Adding a non-Student object should return -1");
    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();

    const student1 = new Student();
    student1.setName('John');
    myClass.addStudent(student1);

    const retrievedStudent = myClass.getStudentById(0);
    assert.strictEqual(retrievedStudent.getName(), 'John', "The student's name should be 'John'");

    const invalidStudent1 = myClass.getStudentById(-1);
    assert.strictEqual(invalidStudent1, null, "Invalid ID (-1) should return null");

    const invalidStudent2 = myClass.getStudentById(10);
    assert.strictEqual(invalidStudent2, null, "ID greater than available range should return null");

    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
    const student = new Student();
    
    student.setName('Alice');
    assert.strictEqual(student.getName(), 'Alice', "The student's name should be 'Alice'");

    student.setName(123);
    assert.strictEqual(student.getName(), 'Alice', "Setting a non-string name should not change the name");
    
    student.setName('');
    assert.strictEqual(student.getName(), '', "The student's name should be '' after setting it to an empty string");

    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();
    
    assert.strictEqual(student.getName(), '', "If name is undefined, it should return an empty string");

    student.setName('Bob');
    assert.strictEqual(student.getName(), 'Bob', "The student's name should be 'Bob'");

    // throw new Error("Test not implemented");
});