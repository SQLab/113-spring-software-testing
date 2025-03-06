const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();
    const myStudent = new Student();
    const invalidStudent = { name : "Not a student"};

    assert.strictEqual(myClass.addStudent(myStudent), 0, 'First is ID 0');
    assert.strictEqual(myClass.addStudent(invalidStudent), 0, 'non-student should return -1');
});

test("Test MyClass's getStudentById", () => {
    // TODO

    const myClass = new MyClass();
    const me = { name : "Brian"};

    const myID = myClass.addStudent(me);

    assert.strictEqual(myClass.getStudentById(myID), 'Brian', 'Should return my name');
    assert.strictEqual(myClass.getStudentById(-1), null, 'should return null if negative');
    assert.strictEqual(myClass.getStudentById(999), null, 'should return null if out-of-range');
});

test("Test Student's setName", () => {
    // TODO

    const myStudent = new Student();

    myStudent.setName(123); //should do nothing with only "return", so cannot test with only this command!
    assert.strictEqual(myStudent.getName(), '', 'should return empty if wrong type');

    myStudent.setName('Brian'); //no "return" any value, so need to test with getName()!
    assert.strictEqual(myStudent.getName(), 'Brian', 'should return the same name');
});

test("Test Student's getName", () => {
    // TODO

    const myStudent = new Student();

    assert.strictEqual(myStudent.getName(), '', 'should return empty if no setup');

    myStudent.setName('Brian');

    assert.strictEqual(myStudent.getName(), 'Brian', 'should return the same name');
});