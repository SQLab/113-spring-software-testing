const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

const calc = new Calculator();

describe('Calculator.exp', () => {
    const errorCases = [
        { input: Infinity, error: 'unsupported operand type' },
        { input: -Infinity, error: 'unsupported operand type' },
        { input: NaN, error: 'unsupported operand type' },
        { input: 1e309, error: 'unsupported operand type' }, // Too large to be finite
        { input: 1000, error: 'overflow' }, // Math.exp(1000) is Infinity
    ];

    errorCases.forEach(({ input, error }) => {
        it(`throws error for exp(${input}) -> ${error}`, () => {
            assert.throws(() => calc.exp(input), { message: error });
        });
    });

    const validCases = [
        { input: 0, expected: 1 },
        { input: 1, expected: Math.E },
        { input: -1, expected: 1 / Math.E },
        { input: Math.log(2), expected: 2 },
    ];

    validCases.forEach(({ input, expected }) => {
        it(`returns correct result for exp(${input})`, () => {
            assert.strictEqual(calc.exp(input), expected);
        });
    });
});

describe('Calculator.log', () => {
    const errorCases = [
        { input: Infinity, error: 'unsupported operand type' },
        { input: -Infinity, error: 'unsupported operand type' },
        { input: NaN, error: 'unsupported operand type' },
        { input: -1, error: 'math domain error (2)' },
        { input: 0, error: 'math domain error (1)' },
    ];

    errorCases.forEach(({ input, error }) => {
        it(`throws error for log(${input}) -> ${error}`, () => {
            assert.throws(() => calc.log(input), { message: error });
        });
    });

    const validCases = [
        { input: 1, expected: 0 },
        { input: Math.E, expected: 1 },
        { input: Math.E ** 2, expected: 2 },
    ];

    validCases.forEach(({ input, expected }) => {
        it(`returns correct result for log(${input})`, () => {
            assert.strictEqual(calc.log(input), expected);
        });
    });
});
