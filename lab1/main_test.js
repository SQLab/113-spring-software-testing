const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();

    const newStudent = new Student();
    newStudent.setName("John");
    const newIndex = myClass.addStudent(newStudent);
    assert.strictEqual(newIndex, 0,"New student's index should be 0.");

    const nonStudent = {};
    const invalidIndex = myClass.addStudent(nonStudent);
    assert.strictEqual(invalidIndex, -1, "Non-student's index should be -1.");

    throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();

    assert.strictEqual(myClass.getStudentById(0), null, "If no student in class, return should be null.");

    const newStudent = new Student();
    newStudent.setName("John");
    const newIndex = myClass.addStudent(newStudent);
    assert.strictEqual(myClass.getStudentById(newIndex), newStudent, "Returned student should be John.");

    assert.strictEqual(myClass.getStudentById(index + 1), null, "If out of index, return should be null.");

    assert.strictEqual(myClass.getStudentById(-1), null, "If input ID < 0, return should be 0.");

    throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    const newStudent = new Student();

    const setInvalidName = newStudent.setName(123);
    assert.strictEqual(setInvalidName, undefined, "Set non-string value, return should be undifined.");

    const setValidName = newStudent.setName("John");
    assert.strictEqual(setValidName, "John", "The student's name should be John.");

    throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    const newStudent = new Student();
    
    const getInvalidName = newStudent.getName();
    assert.strictEqual(getInvalidName, "", "Get undifined name, return should be empty string.");

    newStudent.setName("John");
    const getValidName = newStudent.getName();
    assert.strictEqual(getValidName, "John", "The student's name should be John.");

    throw new Error("Test not implemented");
});