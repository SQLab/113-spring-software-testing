const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
  describe('exp function', () => {
    const expTestCases = [
      { input: 0, expected: 1, description: 'exp of 0' },
      { input: 1, expected: Math.E, description: 'exp of 1' },
      { input: 2, expected: Math.exp(2), description: 'exp of 2' },
      { input: -1, expected: 1/Math.E, description: 'exp of -1' },
      { input: -2, expected: Math.exp(-2), description: 'exp of -2' }
    ];

    expTestCases.forEach(({ input, expected, description }) => {
      it(`should calculate ${description}`, () => {
        const calculator = new Calculator();
        assert.strictEqual(calculator.exp(input), expected);
      });
    });
    
    const expErrorCases = [
      { input: Infinity, expectedError: 'unsupported operand type', description: 'Infinity' },
      { input: -Infinity, expectedError: 'unsupported operand type', description: '-Infinity' },
      { input: NaN, expectedError: 'unsupported operand type', description: 'NaN' },
      { input: 1000, expectedError: 'overflow', description: 'large value' }
    ];
    
    expErrorCases.forEach(({ input, expectedError, description }) => {
      it(`should throw error for ${description}`, () => {
        const calculator = new Calculator();
        assert.throws(() => calculator.exp(input), {
          name: 'Error',
          message: expectedError
        });
      });
    });
  });

  describe('log function', () => {
    const logTestCases = [
      { input: 1, expected: 0, description: 'log of 1' },
      { input: Math.E, expected: 1, description: 'log of e' },
      { input: Math.exp(2), expected: 2, description: 'log of e^2' }
    ];

    logTestCases.forEach(({ input, expected, description }) => {
      it(`should calculate ${description}`, () => {
        const calculator = new Calculator();
        assert.strictEqual(calculator.log(input), expected);
      });
    });
    
    const logErrorCases = [
      { input: -1, expectedError: 'math domain error (2)', description: 'negative number' },
      { input: 0, expectedError: 'math domain error (1)', description: 'zero' },
      { input: Infinity, expectedError: 'unsupported operand type', description: 'Infinity' },
      { input: -Infinity, expectedError: 'unsupported operand type', description: '-Infinity' },
      { input: NaN, expectedError: 'unsupported operand type', description: 'NaN' }
    ];
    
    logErrorCases.forEach(({ input, expectedError, description }) => {
      it(`should throw error for ${description}`, () => {
        const calculator = new Calculator();
        assert.throws(() => calculator.log(input), {
          name: 'Error',
          message: expectedError
        });
      });
    });
  });
});
