const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');


//describe function keeps all info regarding test main functions in one place.
describe('Calculator', () => {
    describe('exp function', () => {
        const calculator = new Calculator();

        //non-error test cases for exp function
        const expTestCases = [
            { input: 0, expected: 1, description: 'exp(0) = 1' },
            { input: 1, expected: Math.E, description: 'exp(1) = e' },
            { input: 2, expected: Math.exp(2), description: 'exp(2)' },
            { input: -1, expected: 1 / Math.E, description: 'exp(-1) = 1/e' },
        ];
        //iterates through each input, asserts strict equal to expected result
        expTestCases.forEach(({ input, expected, description }) => {
            it(`should correctly calculate ${description}`, () => {
                const result = calculator.exp(input);
                assert.strictEqual(result, expected);
            });
        });
        //error cases for exp function
        const expErrorCases = [
            { input: Infinity, expectedError: 'unsupported operand type', description: 'input = Infinity' },
            { input: 1000, expectedError: 'overflow', description: 'very large input (1000)' }
        ];

        expErrorCases.forEach(({ input, expectedError, description }) => {
            it(`should throw "${expectedError}" for ${description}`, () => {
                assert.throws(() => calculator.exp(input), {
                    name: 'Error',
                    message: expectedError
                });
            });
        });
    });
    describe('log function', () => {
        const calculator = new Calculator();

        //non-error test cases for log function
        const logTestCases = [
            { input: 1, expected: 0, description: 'log(1) = 0' },
            { input: Math.log(Math.E), expected: 0, description: 'log(10) = 0' },
            { input: 5, expected: Math.log(5), description: 'log(5)' }
        ];
        //iterates through each input, asserts strict equal to expected result
        logTestCases.forEach(({ input, expected, description }) => {
            it(`should correctly calculate ${description}`, () => {
                const result = calculator.log(input);
                assert.strictEqual(result, expected);
            });
        });
        //error cases for log function
        const expErrorCases = [
            { input: Infinity, expectedError: 'unsupported operand type', description: 'input = Infinity' },
            { input: -Infinity, expectedError: 'unsupported operand type', description: 'input = -Infinity' },
            { input: NaN, expectedError: 'unsupported operand type', description: 'input = NaN' },
            { input: -1, expectedError: 'math domain error (2)', description: 'input = -1' },
            { input: 0, expectedError: 'math domain error (1)', description: 'input = 0' }


        ];

        expErrorCases.forEach(({ input, expectedError, description }) => {
            it(`should throw "${expectedError}" for ${description}`, () => {
                assert.throws(() => calculator.log(input), {
                    name: 'Error',
                    message: expectedError
                });
            });
        });
    });


});
