const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    
    const myClass = new MyClass();
    const student = new Student();
    student.setName('zhiii');

    const studentId = myClass.addStudent(student);
    assert.strictEqual(studentId, 0, 'Student ID should be 0 for the first student');
    //empty object
    const invalidStudentId = myClass.addStudent({});
    assert.strictEqual(invalidStudentId, -1, 'Should return -1 when adding invalid student');
    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName('Gfriend');
    myClass.addStudent(student1);

    const student2 = new Student();
    student2.setName('Apink');
    myClass.addStudent(student2);

    const retrievedStudent = myClass.getStudentById(1);
    assert.strictEqual(retrievedStudent.getName(), 'Apink', 'Should return correct student by ID');

    const invalidStudent = myClass.getStudentById(5);
    assert.strictEqual(invalidStudent, null, 'Should return null for invalid ID');
    //test negative ID
    const invalidStudentNegative = myClass.getStudentById(-1);
    assert.strictEqual(invalidStudentNegative, null, 'Should return null for negative ID');

    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    const student = new Student();
    student.setName('ChoRong');
    assert.strictEqual(student.getName(), 'ChoRong', 'Should set the name correctly');

    student.setName(123);
    assert.strictEqual(student.getName(), 'ChoRong', 'Should not change name if invalid type is provided');
    // test empty string (I think this is not that necessary?)
    student.setName('');
    assert.strictEqual(student.getName(), '', 'Should accept empty string as a valid name');

    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    const student = new Student();
    // test undefined
    assert.strictEqual(student.getName(), '', 'Should return empty string if name is not set');
    student.setName('HaYoung');
    assert.strictEqual(student.getName(), 'HaYoung', 'Should return correct name if set');
    // throw new Error("Test not implemented");
});