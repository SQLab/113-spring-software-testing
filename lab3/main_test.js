const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

const calculator = new Calculator();

// exp() Error Cases
describe('Calculator.exp() Error Cases', () => {
    const errorCases = [
        { param: [NaN], error: 'unsupported operand type' },
        { param: [Infinity], error: 'unsupported operand type' },
        { param: [-Infinity], error: 'unsupported operand type' },
        { param: [1000], error: 'overflow' }
    ];

    for (const tc of errorCases) {
        it(`should throw "${tc.error}" for exp(${tc.param})`, () => {
            assert.throws(() => calculator.exp.apply(calculator, tc.param), { message: tc.error });
        });
    }
});

// exp() Success Cases
describe('Calculator.exp() Success Cases', () => {
    const successCases = [
        { param: [0], expected: 1 },
        { param: [1], expected: Math.exp(1) },
        { param: [-1], expected: Math.exp(-1) }
    ];

    for (const tc of successCases) {
        it(`should return ${tc.expected} for exp(${tc.param})`, () => {
            assert.strictEqual(calculator.exp.apply(calculator, tc.param), tc.expected);
        });
    }
});

// log() Error Cases
describe('Calculator.log() Error Cases', () => {
    const errorCases = [
        { param: [NaN], error: 'unsupported operand type' },
        { param: [Infinity], error: 'unsupported operand type' },
        { param: [-Infinity], error: 'unsupported operand type' },
        { param: [0], error: 'math domain error (1)' },
        { param: [-1], error: 'math domain error (2)' }
    ];

    for (const tc of errorCases) {
        it(`should throw "${tc.error}" for log(${tc.param})`, () => {
            assert.throws(() => calculator.log.apply(calculator, tc.param), { message: tc.error });
        });
    }
});

// log() Success Cases
describe('Calculator.log() Success Cases', () => {
    const successCases = [
        { param: [1], expected: 0 },
        { param: [Math.E], expected: 1 },
        { param: [10], expected: Math.log(10) }
    ];

    for (const tc of successCases) {
        it(`should return ${tc.expected} for log(${tc.param})`, () => {
            assert.strictEqual(calculator.log.apply(calculator, tc.param), tc.expected);
        });
    }
});