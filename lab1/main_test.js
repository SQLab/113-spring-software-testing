const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

// 測試 MyClass 的 addStudent 方法
test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    const student = new Student();
    
    // 新增正確的 Student 物件
    let index = myClass.addStudent(student);
    assert.strictEqual(index, 0);
    assert.strictEqual(myClass.students.length, 1);

    // 嘗試新增非 Student 物件
    index = myClass.addStudent({});
    assert.strictEqual(index, -1);
    assert.strictEqual(myClass.students.length, 1); // 確保長度未變
});

// 測試 MyClass 的 getStudentById 方法
test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    const student1 = new Student();
    student1.setName("Alice");

    const student2 = new Student();
    student2.setName("Bob");

    myClass.addStudent(student1);
    myClass.addStudent(student2);

    // 測試有效 ID
    let result = myClass.getStudentById(0);
    assert.strictEqual(result.getName(), "Alice");

    result = myClass.getStudentById(1);
    assert.strictEqual(result.getName(), "Bob");

    // 測試無效 ID
    result = myClass.getStudentById(-1);
    assert.strictEqual(result, null);

    result = myClass.getStudentById(10);
    assert.strictEqual(result, null);
});

// 測試 Student 的 setName 方法
test("Test Student's setName", () => {
    const student = new Student();

    // 設定正確的名字
    student.setName("Charlie");
    assert.strictEqual(student.getName(), "Charlie");

    // 設定無效的名字（非字串）
    student.setName(12345);
    assert.strictEqual(student.getName(), "Charlie"); // 名字應該不變

    student.setName(null);
    assert.strictEqual(student.getName(), "Charlie"); // 名字應該不變
});

// 測試 Student 的 getName 方法
test("Test Student's getName", () => {
    const student = new Student();

    // 初始 name 應該是空字串
    assert.strictEqual(student.getName(), "");

    // 設定名稱後應該正確返回
    student.setName("David");
    assert.strictEqual(student.getName(), "David");
});
