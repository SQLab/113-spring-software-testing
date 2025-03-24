const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    let calculator;

    beforeEach(() => {
        calculator = new Calculator();
    });

    describe('exp function', () => {
        // 測試正常情況
        const validInputs = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.E },
            { input: -1, expected: 1 / Math.E }
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should correctly calculate exp(${input})`, () => {
                assert.strictEqual(calculator.exp(input), expected);
            });
        });

        // 測試錯誤情況
        const invalidInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
            { input: 1000, error: 'overflow' }
        ];

        invalidInputs.forEach(({ input, error }) => {
            it(`should throw error for exp(${input})`, () => {
                assert.throws(() => calculator.exp(input), {
                    message: error
                });
            });
        });
    });

    describe('log function', () => {
        // 測試正常情況
        const validInputs = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: 10, expected: Math.log(10) }
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should correctly calculate log(${input})`, () => {
                assert.strictEqual(calculator.log(input), expected);
            });
        });

        // 測試錯誤情況
        const invalidInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
            { input: 0, error: 'math domain error (1)' },
            { input: -1, error: 'math domain error (2)' }
        ];

        invalidInputs.forEach(({ input, error }) => {
            it(`should throw error for log(${input})`, () => {
                assert.throws(() => calculator.log(input), {
                    message: error
                });
            });
        });
    });
});
