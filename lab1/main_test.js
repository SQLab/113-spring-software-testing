const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // Create a new MyClass instance
    const myClass = new MyClass();
    
    // Test with valid Student instance
    const student = new Student();
    const id = myClass.addStudent(student);
    assert.strictEqual(id, 0);
    assert.strictEqual(myClass.students.length, 1);
    
    // Test with another valid Student instance
    const student2 = new Student();
    const id2 = myClass.addStudent(student2);
    assert.strictEqual(id2, 1);
    assert.strictEqual(myClass.students.length, 2);
    
    // Test with invalid input (not a Student instance)
    const invalidId = myClass.addStudent({});
    assert.strictEqual(invalidId, -1);
    assert.strictEqual(myClass.students.length, 2);
});

test("Test MyClass's getStudentById", () => {
    // Create a new MyClass instance
    const myClass = new MyClass();
    
    // Add a student
    const student = new Student();
    student.setName("Test Student");
    const id = myClass.addStudent(student);
    
    // Test with valid id
    const retrievedStudent = myClass.getStudentById(id);
    assert.strictEqual(retrievedStudent, student);
    
    // Test with negative id
    const nullStudent1 = myClass.getStudentById(-1);
    assert.strictEqual(nullStudent1, null);
    
    // Test with out-of-bounds id
    const nullStudent2 = myClass.getStudentById(999);
    assert.strictEqual(nullStudent2, null);
});

test("Test Student's setName", () => {
    // Create a new Student instance
    const student = new Student();
    
    // Test with valid string
    student.setName("John Doe");
    assert.strictEqual(student.name, "John Doe");
    
    // Test with another valid string
    student.setName("Jane Smith");
    assert.strictEqual(student.name, "Jane Smith");
    
    // Test with invalid input (not a string)
    const originalName = student.name;
    student.setName(123);
    assert.strictEqual(student.name, originalName); // Name should not change
    
    student.setName(null);
    assert.strictEqual(student.name, originalName); // Name should not change
    
    student.setName(undefined);
    assert.strictEqual(student.name, originalName); // Name should not change
    
    student.setName({});
    assert.strictEqual(student.name, originalName); // Name should not change
});

test("Test Student's getName", () => {
    // Create a new Student instance
    const student = new Student();
    
    // Test with undefined name (initial state)
    assert.strictEqual(student.getName(), '');
    
    // Test with defined name
    student.setName("John Doe");
    assert.strictEqual(student.getName(), "John Doe");
    
    // Test with empty string
    student.setName("");
    assert.strictEqual(student.getName(), "");
});