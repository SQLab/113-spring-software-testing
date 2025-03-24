const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    const calculator = new Calculator();

    describe('exp(x)', () => {
        const validInputs = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.exp(1) },
            { input: -1, expected: Math.exp(-1) },
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should return ${expected} for exp(${input})`, () => {
                assert.strictEqual(calculator.exp(input), expected);
            });
        });

        const invalidInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
        ];

        invalidInputs.forEach(({ input, error }) => {
            it(`should throw "${error}" for exp(${input})`, () => {
                assert.throws(() => calculator.exp(input), { message: error });
            });
        });

        it('should throw "overflow" when result is Infinity (large input)', () => {
            assert.throws(() => calculator.exp(1000), { message: 'overflow' });
        });
    });

    describe('log(x)', () => {
        const validInputs = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: 10, expected: Math.log(10) },
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should return ${expected} for log(${input})`, () => {
                assert.strictEqual(calculator.log(input), expected);
            });
        });

        const invalidInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
        ];

        invalidInputs.forEach(({ input, error }) => {
            it(`should throw "${error}" for log(${input})`, () => {
                assert.throws(() => calculator.log(input), { message: error });
            });
        });

        it('should throw "math domain error (1)" for log(0)', () => {
            assert.throws(() => calculator.log(0), { message: 'math domain error (1)' });
        });

        it('should throw "math domain error (2)" for log(-1)', () => {
            assert.throws(() => calculator.log(-1), { message: 'math domain error (2)' });
        });
    });
});
