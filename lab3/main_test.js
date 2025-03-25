const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    const calculator = new Calculator();

    describe('exp', () => {
        const expErrorCases = [
            { input: Infinity, message: 'unsupported operand type' },
            { input: 48763, message: 'overflow' },
        ];

        expErrorCases.forEach(({ input, message }) => {
            it(`exp(${input}) should throw "${message}"`, () => {
                assert.throws(
                    () => calculator.exp(input),
                    { message },
                    `exp(${input}) should throw "${message}"`
                );
            });
        });

        const expValidCases = [
            { input: 1, expected: Math.exp(1) },
            { input: 0, expected: Math.exp(0) },
        ];

        expValidCases.forEach(({ input, expected }) => {
            it(`exp(${input}) should return ${expected}`, () => {
                assert.strictEqual(
                    calculator.exp(input),
                    expected,
                    `exp(${input}) should return ${expected}`
                );
            });
        });
    });

    describe('log', () => {
        const logErrorCases = [
            { input: Infinity, message: 'unsupported operand type' },
            { input: 0, message: 'math domain error (1)' },
            { input: -1, message: 'math domain error (2)' },
        ];

        logErrorCases.forEach(({ input, message }) => {
            it(`log(${input}) should throw "${message}"`, () => {
                assert.throws(
                    () => calculator.log(input),
                    { message },
                    `log(${input}) should throw "${message}"`
                );
            });
        });

        const logValidCases = [
            { input: Math.E, expected: 1 },
            { input: 1, expected: 0 },
            { input: 10, expected: Math.log(10) },
        ];

        logValidCases.forEach(({ input, expected }) => {
            it(`log(${input}) should return ${expected}`, () => {
                assert.strictEqual(
                    calculator.log(input),
                    expected,
                    `log(${input}) should return ${expected}`
                );
            });
        });
    });
});
