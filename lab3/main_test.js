const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe('Calculator', () => {
    describe('exp', () => {
        const errorCases = [
            { input: null, expectedError: 'unsupported operand type' },
            { input: 'abc', expectedError: 'unsupported operand type' },
            { input: 1000, expectedError: 'overflow' }
        ];
        const successCases = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.E },
            { input: -1, expected: 1/Math.E }
        ];

        errorCases.forEach(({ input, expectedError }) => {
            it(`exp(${JSON.stringify(input)}) should throw ${expectedError}`, () => {
                const calc = new Calculator();
                assert.throws(() => calc.exp(input), { message: expectedError });
            });
        });

        successCases.forEach(({ input, expected }) => {
            it(`exp(${input}) should return ${expected}`, () => {
                const calc = new Calculator();
                assert.strictEqual(calc.exp(input), expected);
            });
        });
    });

    describe('log', () => {
        const errorCases = [
            { input: undefined, expectedError: 'unsupported operand type' },
            { input: 0, expectedError: 'math domain error (1)' },
            { input: -5, expectedError: 'math domain error (2)' }
        ];

        const successCases = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: 10, expected: Math.log(10) }
        ];

        errorCases.forEach(({ input, expectedError }) => {
            it(`log(${JSON.stringify(input)}) should throw ${expectedError}`, () => {
                const calc = new Calculator();
                assert.throws(() => calc.log(input), { message: expectedError });
            });
        });

        successCases.forEach(({ input, expected }) => {
            it(`log(${input}) should return ${expected}`, () => {
                const calc = new Calculator();
                assert.strictEqual(calc.log(input), expected);
            });
        });
    });
});