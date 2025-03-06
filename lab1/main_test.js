const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
 
    // Create an instance of MyClass
    const myClass = new MyClass();

    // Test 1: Passing a non-Student object should return -1
    assert.strictEqual(myClass.addStudent("Jonh"), -1, "test 1 at addStudent");

    // Test 2: Adding a valid Student object should return index 0
    const student0 = new Student();
    student0.setName("John");
    assert.strictEqual(myClass.addStudent(student0), 0, "test 2 at addStudent");

    // Test 3: Adding another Student should return index 1 (Fix the expected value)
    const student1 = new Student();
    student1.setName("Jane");
    assert.strictEqual(myClass.addStudent(student1), 1, "test 3 at addStudent");

    // No need to throw an error; tests are implemented
    // throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    
    // Create an instance of MyClass
    const myClass = new MyClass();

    // add student
    const student0 = new Student(), student1 = new Student(), student2 = new Student();
    student0.setName("Doe");

    const newStudentId0 = myClass.addStudent(student0);

    // Test 1: Passing an invalid ID (< 0) should return null
    assert.strictEqual(myClass.getStudentById(-1), null, "test 1 at getStudentById");

    // Test 2: Valid ID should return the correct student object
    assert.strictEqual(myClass.getStudentById(newStudentId0), student0, "test 2 at getStudentById");

    // Test 3: Passing an out-of-bounds ID should return null
    assert.strictEqual(myClass.getStudentById(999), null, "test 3 at getStudentById");
    
    // No need to throw an error; tests are implemented
    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {

    // Test 1: userName is an integer, should not change name (remain undefined)
    const student0 = new Student();
    const name0= 20250306;
    student0.setName(name0);
    assert.strictEqual(student0.getName(), '', "test 1 at setName");

    // Test 2: userName is a float, should not change name (remain undefined)
    const student1 = new Student();
    const name1= 3.14156;
    student1.setName(name1);
    assert.strictEqual(student1.getName(), '', "test 2 at setName");

    // Test 3: userName is a valid string, should set the name correctly
    const student2 = new Student();
    const name3= 'Smith';
    student2.setName(name3);
    assert.strictEqual(student2.getName(), name3, "test 3 at setName");

    // No need to throw an error; tests are implemented
    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {

    // Test 1: Set a valid name and retrieve it
    const student0 = new Student();
    const name0 = "John";
    student0.setName(name0);
    assert.strictEqual(student0.getName(), name0, "test 1 at getName");

    // Test 2: Set an invalid name (integer), getName() should return an empty string
    const student1 = new Student();
    student1.setName(1);
    assert.strictEqual(student1.getName(), '', "test 2 at getName");

    // Test 3: Set an empty string as name, should return an empty string
    const student2 = new Student();
    student2.setName('');
    assert.strictEqual(student2.getName(), '', "test 3 at getName");

    // Test 4: Default value of getName() before setting any name
    const student3 = new Student();
    assert.strictEqual(student3.getName(), '', "test 4 at getName");

    // No need to throw an error; tests are implemented
    // throw new Error("Test not implemented");
});