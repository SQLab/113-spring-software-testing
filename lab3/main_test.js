const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('exp()', () => {
  const calculator = new Calculator();

  const validExpTestCases = [
    { input: 0, expected: 1 },
    { input: 1, expected: Math.exp(1) },
    { input: 2.5, expected: Math.exp(2.5) },
    { input: -1, expected: Math.exp(-1) }
  ];

  validExpTestCases.forEach(({ input, expected }) => {
    it(`should return ${expected} for exp(${input})`, () => {
      assert.strictEqual(calculator.exp(input), expected);
    });
  });

  const expErrorTestCases = [
    { input: Infinity, error: 'unsupported operand type' },
    { input: -Infinity, error: 'unsupported operand type' },
    { input: NaN, error: 'unsupported operand type' },
    { input: 1000, error: 'overflow' }
  ];

  expErrorTestCases.forEach(({ input, error }) => {
    it(`should throw "${error}" for exp(${input})`, () => {
      assert.throws(() => calculator.exp(input), { message: error });
    });
  });
});

describe('log()', () => {
  const calculator = new Calculator();

  const validLogTestCases = [
    { input: 1, expected: 0 },
    { input: Math.E, expected: 1 },
    { input: 10, expected: Math.log(10) },
    { input: 100, expected: Math.log(100) }
  ];

  validLogTestCases.forEach(({ input, expected }) => {
    it(`should return ${expected} for log(${input})`, () => {
      assert.strictEqual(calculator.log(input), expected);
    });
  });

  const logErrorTestCases = [
    { input: Infinity, error: 'unsupported operand type' },
    { input: -Infinity, error: 'unsupported operand type' },
    { input: NaN, error: 'unsupported operand type' },
    { input: 0, error: /math domain error \(1\)/ },
    { input: -1, error: /math domain error \(2\)/ }
  ];

  logErrorTestCases.forEach(({ input, error }) => {
    it(`should throw "${error}" for log(${input})`, () => {
      assert.throws(() => calculator.log(input), new RegExp(error));
    });
  });
});
