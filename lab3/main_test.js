const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

const calc = new Calculator();

describe('Calculator.exp()', () => {
    const validCases = [
        { input: 0, expected: 1 },
        { input: 1, expected: Math.exp(1) },
        { input: -1, expected: Math.exp(-1) }
    ];

    validCases.forEach(({ input, expected }) => {
        it(`should return ${expected} for exp(${input})`, () => {
            assert.strictEqual(calc.exp(input), expected);
        });
    });

    const errorCases = [
        { input: Infinity, error: 'unsupported operand type' },
        { input: -Infinity, error: 'unsupported operand type' },
        { input: 'hello', error: 'unsupported operand type' }, // NaN
        { input: 99999, error: 'overflow' } // force large number
    ];

    errorCases.forEach(({ input, error }) => {
        it(`should throw "${error}" for exp(${input})`, () => {
            assert.throws(() => calc.exp(input), new Error(error));
        });
    });
});

describe('Calculator.log()', () => {
    const validCases = [
        { input: 1, expected: 0 },
        { input: Math.E, expected: 1 },
        { input: 10, expected: Math.log(10) }
    ];

    validCases.forEach(({ input, expected }) => {
        it(`should return ${expected} for log(${input})`, () => {
            assert.strictEqual(calc.log(input), expected);
        });
    });

    const errorCases = [
        { input: 0, error: 'math domain error (1)' },
        { input: -1, error: 'math domain error (2)' },
        { input: Infinity, error: 'unsupported operand type' },
        { input: NaN, error: 'unsupported operand type' },
        { input: 'world', error: 'unsupported operand type' }
    ];

    errorCases.forEach(({ input, error }) => {
        it(`should throw "${error}" for log(${input})`, () => {
            assert.throws(() => calc.log(input), new Error(error));
        });
    });
});
