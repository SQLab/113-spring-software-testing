const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

// 測試 MyClass 的 addStudent 方法
test("Test MyClass's addStudent", () => {
    const myClass = new MyClass();
    
    // 測試加入有效的 Student 物件
    const student1 = new Student();
    student1.setName("Alice");
    const idx1 = myClass.addStudent(student1);
    assert.strictEqual(idx1, 0);

    // 測試加入另一個有效的 Student 物件
    const student2 = new Student();
    student2.setName("Bob");
    const idx2 = myClass.addStudent(student2);
    assert.strictEqual(idx2, 1);

    // 測試加入非 Student 實例（例如一個物件）應回傳 -1
    const result = myClass.addStudent({ name: "Charlie" });
    assert.strictEqual(result, -1);
});

// 測試 MyClass 的 getStudentById 方法
test("Test MyClass's getStudentById", () => {
    const myClass = new MyClass();
    
    // 加入一個 Student，取得其 index
    const student = new Student();
    student.setName("David");
    const index = myClass.addStudent(student);

    // 測試取得存在的 student
    const retStudent = myClass.getStudentById(index);
    assert.strictEqual(retStudent, student);

    // 測試取得負數 index 應回傳 null
    assert.strictEqual(myClass.getStudentById(-1), null);

    // 測試取得超出範圍的 index 應回傳 null
    assert.strictEqual(myClass.getStudentById(100), null);
});

// 測試 Student 的 setName 方法
test("Test Student's setName", () => {
    const student = new Student();

    // 設定有效字串後，檢查 name 屬性是否正確
    student.setName("Eve");
    assert.strictEqual(student.name, "Eve");

    // 傳入非字串的參數，name 應保持原值不變
    student.setName(123);
    assert.strictEqual(student.name, "Eve");
});

// 測試 Student 的 getName 方法
test("Test Student's getName", () => {
    const student = new Student();

    // 未設定 name 時，getName 應回傳空字串
    assert.strictEqual(student.getName(), "");

    // 設定 name 後，getName 應回傳該字串
    student.setName("Frank");
    assert.strictEqual(student.getName(), "Frank");
});
