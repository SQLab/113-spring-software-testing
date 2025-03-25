const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
const calculator = new Calculator();

describe('Calculator.exp', () => {
  describe('Test error-results', () => {
    const testcases = [
      { input: Infinity, error: 'unsupported operand type' },
      { input: -Infinity, error: 'unsupported operand type' },
      { input: NaN, error: 'unsupported operand type' },
      { input: 1000, error: 'overflow' }
    ];
    testcases.forEach(({ input, error }) => {
      it(`should throw Error "${error}" for exp(${input})`, () => {
        assert.throws(() => calculator.exp(input), new Error(error));
      });
    });
  });

  describe('Test non-error-results', () => {
    const testcases = [
      { input: 0, expected: Math.exp(0) },
      { input: 1, expected: Math.exp(1) },
      { input: -1, expected: Math.exp(-1) }
    ];
    testcases.forEach(({ input, expected }) => {
      it(`should return ${expected} for exp(${input})`, () => {
        const result = calculator.exp(input);
        assert.strictEqual(result, expected);
      });
    });
  });
});

describe('Calculator.log', () => {
  describe('Test error-results', () => {
    const testcases = [
      { input: Infinity, error: 'unsupported operand type' },
      { input: -Infinity, error: 'unsupported operand type' },
      { input: NaN, error: 'unsupported operand type' },
      { input: 0, error: 'math domain error (1)' },
      { input: -1, error: 'math domain error (2)' }
    ];
    testcases.forEach(({ input, error }) => {
      it(`should throw Error("${error}") for log(${input})`, () => {
        assert.throws(() => calculator.log(input), new Error(error));
      });
    });
  });

  describe('Test non-error-results', () => {
    const testcases = [
      { input: 1, expected: Math.log(1) },
      { input: 10, expected: Math.log(10) },
      { input: 2.71828, expected: Math.log(2.71828) }
    ];
    testcases.forEach(({ input, expected }) => {
      it(`should return approximately ${expected} for log(${input})`, () => {
        const result = calculator.log(input);
        assert.ok(Math.abs(result - expected) < 1e-10); // tolerance
      });
    });
  });
});
