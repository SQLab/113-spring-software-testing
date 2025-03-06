const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
    const myClass = new MyClass();
    // Test not instance of
    const notStudent = 'John';
    const notStudentId = myClass.addStudent(notStudent);
    
    const names = ['John', 'Jane', 'Doe', 'Smith'];
    names.forEach(name => {
	const student = new Student();
	student.setName(name);
	const newStudentId = myClass.addStudent(student);
	const newStudentName = myClass.getStudentById(newStudentId).getName();
	console.log('[+] Added student with id: %d, name: %s', newStudentId, newStudentName);});
});

test("Test MyClass's getStudentById", () => {
    // TODO
    const myClass = new MyClass();
    // Test empty class
    const emptyIds = [-1, 0, 1];
    emptyIds.forEach(id => {
	const student = myClass.getStudentById(id);
	assert.strictEqual(student, null);
    });
    // Test class with students
    const names = ['John', 'Jane', 'Doe', 'Smith'];
    names.forEach(name => {
	const student = new Student();
	student.setName(name);
	const newStudentId = myClass.addStudent(student);
    });
    const validIds = [0, 1, 2, 3];
    validIds.forEach(id => {
	const student = myClass.getStudentById(id);
	assert.strictEqual(student.getName(), names[id]);
    });
    
    const invalidIds = [-1, 4, 5];
    invalidIds.forEach(id => {
	const student = myClass.getStudentById(id);
	assert.strictEqual(student, null);
    }); 
});

test("Test Student's setName", () => {
    // TODO
    // Test not string
    const student = new Student();
    student.setName(123);
    assert.strictEqual(student.name, undefined);
    // Test string
    student.setName('John');
    assert.strictEqual(student.name, 'John');
});

test("Test Student's getName", () => {
    // TODO
    const student = new Student();
    // Test undefined
    assert.strictEqual(student.getName(), '');
    // Test defined
    student.setName('John');
    assert.strictEqual(student.getName(), 'John');
    
});
