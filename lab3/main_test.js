const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('Calculator', () => {
    const calculator = new Calculator();

    describe('exp()', () => {
        const invalidInputs = [Infinity, -Infinity, NaN];
        invalidInputs.forEach((input) => {
            it(`should throw 'unsupported operand type' for input: ${input}`, () => {
                assert.throws(() => calculator.exp(input), {
                    message: 'unsupported operand type'
                });
            });
        });

        it('should throw "overflow" for very large input', () => {
            assert.throws(() => calculator.exp(1000), {
                message: 'overflow'
            });
        });

        const validExpInputs = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.E },
            { input: 2, expected: Math.exp(2) }
        ];
        validExpInputs.forEach(({ input, expected }) => {
            it(`should return ${expected} for exp(${input})`, () => {
                const result = calculator.exp(input);
                assert.strictEqual(result, expected);
            });
        });
    });

    describe('log()', () => {
        const invalidInputs = [Infinity, -Infinity, NaN];
        invalidInputs.forEach((input) => {
            it(`should throw 'unsupported operand type' for input: ${input}`, () => {
                assert.throws(() => calculator.log(input), {
                    message: 'unsupported operand type'
                });
            });
        });

        it('should throw "math domain error (1)" for 0', () => {
            assert.throws(() => calculator.log(0), {
                message: 'math domain error (1)'
            });
        });

        it('should throw "math domain error (2)" for negative number', () => {
            assert.throws(() => calculator.log(-1), {
                message: 'math domain error (2)'
            });
        });

        const validLogInputs = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: Math.exp(2), expected: 2 }
        ];
        validLogInputs.forEach(({ input, expected }) => {
            it(`should return ${expected} for log(${input})`, () => {
                const result = calculator.log(input);
                assert.ok(Math.abs(result - expected) < 1e-12);
            });
        });
    });
});
