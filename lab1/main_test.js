const test = require('node:test');
const assert = require('assert');
const { MyClass, Student } = require('./main');

test("Test MyClass's addStudent", () => {
    // TODO
	
	const myClass = new MyClass();

	const student = new Student();
	student.setName("Kodak");
	const id = myClass.addStudent(student);
	assert.strictEqual(id, 0);

	// 測試新增第二個學生
	const student2 = new Student();
	student2.setName("Contax");
	const id2 = myClass.addStudent(student2);
	assert.strictEqual(id2, 1); // 第二個學生的 ID 應該是 1

	// 測試新增非 Student 實例
	const invalidStudent = { name: "Invalid" };
	const invalidId = myClass.addStudent(invalidStudent);
	assert.strictEqual(invalidId, -1); // 應該返回 -1

    //throw new Error("Test not implemented");
});

test("Test MyClass's getStudentById", () => {
    // TODO

	const myClass = new MyClass();
    const student = new Student();
    student.setName("Kodak");
    myClass.addStudent(student);
    
    // 測試有效的 ID
    const foundStudent = myClass.getStudentById(0);
    assert.strictEqual(foundStudent, student);
    
    // 測試負數 ID
    const nullStudent1 = myClass.getStudentById(-1);
    assert.strictEqual(nullStudent1, null);
    
    // 測試超出範圍的 ID
    const nullStudent2 = myClass.getStudentById(999);
    assert.strictEqual(nullStudent2, null);
    //throw new Error("Test not implemented");
});

test("Test Student's setName", () => {
    // TODO
	const student = new Student();
    
    // 測試設定有效的名字
    student.setName("Kodak");
    assert.strictEqual(student.getName(), "Kodak");
    
    // 測試設定空字串
    student.setName("");
    assert.strictEqual(student.getName(), "");
    
    // 測試設定非字串值
    student.setName(123); // 應該被忽略
    assert.strictEqual(student.getName(), ""); // 名字應該保持不變
    
    student.setName(null); // 應該被忽略
    assert.strictEqual(student.getName(), ""); // 名字應該保持不變
    
    student.setName(undefined); // 應該被忽略
    assert.strictEqual(student.getName(), ""); // 名字應該保持不變
    //throw new Error("Test not implemented");
});

test("Test Student's getName", () => {
    // TODO
	const student = new Student();
    
    // 測試初始狀態（未設定名字）
    assert.strictEqual(student.getName(), "");
    
    // 測試設定名字後的狀態
    student.setName("Kodak");
    assert.strictEqual(student.getName(), "Kodak");
    
    // 測試設定空字串
    student.setName("");
    assert.strictEqual(student.getName(), "");
    
    // 直接修改 name 為 undefined
    student.name = undefined;
    assert.strictEqual(student.getName(), "");
    //throw new Error("Test not implemented");
});
