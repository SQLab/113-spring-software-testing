const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    const stud = new Student();
    const myclass = new MyClass();
    assert.strictEqual(myclass.addStudent(stud),0);
    assert.strictEqual(myclass.addStudent(5),-1);
    //throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () =>{
    const stud = new Student();
    const myclass = new MyClass();
    myclass.addStudent(stud);
    assert.strictEqual(myclass.getStudentById(0),stud);
    assert.strictEqual(myclass.getStudentById(-1),null);
    assert.strictEqual(myclass.getStudentById(10),null);
    // throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    const stud = new Student();
    assert.strictEqual(stud.setName("name"),undefined);
    assert.strictEqual(stud.setName(1),undefined);
    // throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    const stud = new Student();
    stud.setName("name1");
    const stud1 = new Student();
    assert.strictEqual(stud.getName(),"name1");
    assert.strictEqual(stud1.getName(),'');
    // throw new Error("Test not implemented");
});
