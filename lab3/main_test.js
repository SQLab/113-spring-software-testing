const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('test exp error', () => {
    // test if exp throw error
    const errorTestcases = [
        { param: 'NaN', expected: Error },
        { param: 'Infinity', expected: Error },
        { param: '-Infinity', expected: Error }
    ]
    const calculator = new Calculator();
    for (const testcase of errorTestcases) {
        assert.throws(() => calculator.exp(testcase.param), testcase.expected);
    }
    // test if exp return value
    const validTestcases = [
        { param: 1, expected: Math.exp(1) },
        { param: -1, expected: Math.exp(-1) },
        { param: 0, expected: Math.exp(0) }
    ]
    for (const testcase of validTestcases) {
        assert.strictEqual(calculator.exp(testcase.param), testcase.expected);
    }
    // test if exp throw error when overflow
    const overflowTestcases = [
        { param: 1000, expected: Error },
        { param: Infinity, expected: Error }
    ]
    for (const testcase of overflowTestcases) {
        assert.throws(() => calculator.exp(testcase.param), testcase.expected);
    }
    // test if exp return value when not overflow
    const extremeTestcases = [
        { param: -1000, expected: Math.exp(-1000) },  // 非常接近 0 但不是 0
        { param: 500, expected: Math.exp(500) }       // 很大但不會溢出
    ]
    for (const testcase of extremeTestcases) {
        assert.strictEqual(calculator.exp(testcase.param), testcase.expected);
    }
});

describe('test log error', () => {
    // test if log throw error
    const errorTestcases = [
        { param: 'NaN', expected: Error },
        { param: 'Infinity', expected: Error },
        { param: '-Infinity', expected: Error },
        { param: 0, expected: Error },
        { param: -0, expected: Error },
        { param: -1, expected: Error }
    ];
    
    const calculator = new Calculator();
    
    // test if log throw error
    for (const testcase of errorTestcases) {
        it(`should throw error for ${testcase.param}`, () => {
            assert.throws(() => calculator.log(testcase.param), testcase.expected);
        });
    }
    
    // test if log return value
    const validTestcases = [
        { param: 1, expected: Math.log(1) },
        { param: 2, expected: Math.log(2) },
        { param: 10, expected: Math.log(10) }
    ];
    
    // test if log return value
    for (const testcase of validTestcases) {
        it(`should return ${testcase.expected} for ${testcase.param}`, () => {
            assert.strictEqual(calculator.log(testcase.param), testcase.expected);
        });
    }
});
