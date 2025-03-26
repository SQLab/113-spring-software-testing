const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
const calculator = new Calculator();

describe('Calculator', () => {
    describe('exp()', () => {
        const validInputs = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.exp(1) },
            { input: -1, expected: Math.exp(-1) },
            { input: 5, expected: Math.exp(5) },
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should return correct result for exp(${input})`, () => {
                assert.strictEqual(calculator.exp(input), expected);
            });
        });

        const errorInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: 'string', error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
        ];

        errorInputs.forEach(({ input, error }) => {
            it(`should throw error "${error}" for exp(${input})`, () => {
                assert.throws(() => calculator.exp(input), { message: error });
            });
        });

        it('should throw "overflow" when result is Infinity', () => {
            // Use a very large number to trigger overflow
            const input = 1e308;
            assert.throws(() => calculator.exp(input), { message: 'overflow' });
        });
    });

    describe('log()', () => {
        const validInputs = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: 10, expected: Math.log(10) },
            { input: 0.5, expected: Math.log(0.5) },
        ];

        validInputs.forEach(({ input, expected }) => {
            it(`should return correct result for log(${input})`, () => {
                assert.strictEqual(calculator.log(input), expected);
            });
        });

        const errorInputs = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: NaN, error: 'unsupported operand type' },
            { input: 'abc', error: 'unsupported operand type' },
        ];

        errorInputs.forEach(({ input, error }) => {
            it(`should throw error "${error}" for log(${input})`, () => {
                assert.throws(() => calculator.log(input), { message: error });
            });
        });

        it('should throw "math domain error (1)" when result is -Infinity', () => {
            assert.throws(() => calculator.log(0), { message: 'math domain error (1)' });
        });

        it('should throw "math domain error (2)" when result is NaN', () => {
            assert.throws(() => calculator.log(-1), { message: 'math domain error (2)' });
        });
    });
});