const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    describe('exp', () => {
        const calculator = new Calculator();

        it('should throw "unsupported operand type" for non-finite numbers', () => {
            const invalidInputs = [NaN, Infinity, -Infinity, 'string', null, undefined];
            invalidInputs.forEach(input => {
                assert.throws(() => calculator.exp(input), Error('unsupported operand type'));
            });
        });

        it('should throw "overflow" for large numbers', () => {
            const largeInputs = [1000, 10000, 100000];
            largeInputs.forEach(input => {
                assert.throws(() => calculator.exp(input), Error('overflow'));
            });
        });

        it('should return correct exp value for valid inputs', () => {
            const testCases = [
                { input: 0, expected: 1 },
                { input: 1, expected: Math.exp(1) },
                { input: -1, expected: Math.exp(-1) },
            ];
            testCases.forEach(({ input, expected }) => {
                assert.strictEqual(calculator.exp(input), expected);
            });
        });
    });

    describe('log', () => {
        const calculator = new Calculator();

        it('should throw "unsupported operand type" for non-finite numbers', () => {
            const invalidInputs = [NaN, Infinity, -Infinity, 'string', null, undefined];
            invalidInputs.forEach(input => {
                assert.throws(() => calculator.log(input), Error('unsupported operand type'));
            });
        });

        it('should throw "math domain error (1)" for zero', () => {
            const invalidInputs = [0];
            invalidInputs.forEach(input => {
                assert.throws(() => calculator.log(input), Error('math domain error (1)'));
            });
        });

        it('should throw "math domain error (2)" for finite negative numbers', () => {
            const invalidInputs = [-1, -5, -100];
            invalidInputs.forEach(input => {
                assert.throws(() => calculator.log(input), Error('math domain error (2)'));
            });
        });

        it('should return correct log value for valid inputs', () => {
            const testCases = [
                { input: 1, expected: 0 },
                { input: Math.E, expected: 1 },
                { input: 10, expected: Math.log(10) },
            ];
            testCases.forEach(({ input, expected }) => {
                assert.strictEqual(calculator.log(input), expected);
            });
        });
    });
});