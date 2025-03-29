const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

const calculator = new Calculator();

describe('Calculator', () => {
    describe('exp', () => {
        const validCases = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.exp(1) },
            { input: -1, expected: Math.exp(-1) },
        ];

        validCases.forEach(({ input, expected }) => {
            it(`exp(${input}) should return ${expected}`, () => {
                assert.ok(Math.abs(calculator.exp(input) - expected) < 1e-10);
            });
        });

        const errorCases = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: 1000, error: 'overflow' },
        ];

        errorCases.forEach(({ input, error }) => {
            it(`exp(${input}) should throw '${error}'`, () => {
                assert.throws(() => calculator.exp(input), err => err.message === error);
            });
        });
    });

    describe('log', () => {
        const validCases = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: 10, expected: Math.log(10) },
        ];

        validCases.forEach(({ input, expected }) => {
            it(`log(${input}) should return ${expected}`, () => {
                assert.ok(Math.abs(calculator.log(input) - expected) < 1e-10);
            });
        });

        const errorCases = [
            { input: Infinity, error: 'unsupported operand type' },
            { input: -Infinity, error: 'unsupported operand type' },
            { input: 0, error: 'math domain error (1)' },
            { input: -10, error: 'math domain error (2)' },
            { input: NaN, error: 'unsupported operand type' },
        ];

        errorCases.forEach(({ input, error }) => {
            it(`log(${input}) should throw '${error}'`, () => {
                assert.throws(() => calculator.log(input), err => err.message === error);
            });
        });
    });
});
