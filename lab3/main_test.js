const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('test exp',() => {
    const cal = new Calculator
    it('test error-exp', () => {
        const testcase = [
            {param : "string", expected : "unsupported operand type"},
            {param : NaN, expected : "unsupported operand type"} ,        
            {param : 1000, expected : "overflow"},
        ]

        for (const tc of testcase){
            assert.throws(() => {cal.exp(tc.param)}, {message : tc.expected});
        }
    });
    it('test normal-exp',() => {
        const testcase = [
            {param : 3, expected : Math.exp(3)},
            {param : 100, expected : Math.exp(100)},
            {param : 125, expected : Math.exp(125)}
        ]
    
        for (const tc of testcase){
            assert.strictEqual(cal.exp(tc.param), tc.expected)
        }        
    })
});
describe('test log',() => {
    const cal = new Calculator
    it('test error-log', () => {
        const testcase = [
            {param : "string", expected : "unsupported operand type"},
            {param : 0, expected : "math domain error (1)"},
            {param : -1, expected : "math domain error (2)"},
        ]
    
        for (const tc of testcase){
            assert.throws(() => {cal.log(tc.param)}, {message : tc.expected});
        }
    });
    it('test normal-log',() => {
        const testcase = [
            {param : 12, expected : Math.log(12)},
            {param : 36, expected : Math.log(36)},
            {param : 64, expected : Math.log(64)}
        ]
    
        for (const tc of testcase){
            assert.strictEqual(cal.log(tc.param), tc.expected)
        }
    })
});