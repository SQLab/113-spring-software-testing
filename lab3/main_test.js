const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe("Test Calculator exp", () => {
    const cal = new Calculator();
    const testcases = [
        {param: 0, expected: 1},
        {param: 1, expected: Math.E}
    ];
    const testcasesError = [
        {param: "haha", expected: 'unsupported operand type'},
        {param: Infinity, expected: 'unsupported operand type'},
        {param: 1000, expected: 'overflow'}
    ];

    for(const tc of testcases){
        assert.strictEqual(cal.exp(tc.param), tc.expected);
    } 
    for(const tc of testcasesError){
        assert.throws(()=>{
            cal.exp(tc.param);
        },{
            name: 'Error',
            message: tc.expected
        });
    } 
});

describe("Test Calculator log", () => {
    const cal = new Calculator();
    const testcases = [
        {param: 1, expected: 0},
        {param: Math.E, expected: 1}
    ];
    const testcasesError = [
        {param: "haha", expected: 'unsupported operand type'},
        {param: 0, expected: 'math domain error (1)'},
        {param: -1, expected: 'math domain error (2)'}
    ];

    for(const tc of testcases){
        assert.strictEqual(cal.log(tc.param), tc.expected);
    } 
    for(const tc of testcasesError){
        assert.throws(()=>{
            cal.log(tc.param);
        },{
            name: 'Error',
            message: tc.expected
        });
    } 
});