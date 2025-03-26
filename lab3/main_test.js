
const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator.exp', () => {
  const calc = new Calculator();

  // Non-error test cases (at least 3)
  const validExpCases = [
    { input: 0, expected: Math.exp(0) },       // exp(0) = 1
    { input: 1, expected: Math.exp(1) },       // exp(1) ≈ 2.71828
    { input: -1, expected: Math.exp(-1) }      // exp(-1) ≈ 0.36788
  ];
  validExpCases.forEach(({ input, expected }) => {
    it(`should return ${expected} for exp(${input})`, () => {
      const result = calc.exp(input);
      assert.strictEqual(result, expected);
    });
  });

  // Error test cases (parameterized)
  const errorExpCases = [
    { input: Infinity, errorMsg: 'unsupported operand type' },
    { input: -Infinity, errorMsg: 'unsupported operand type' },
    { input: NaN, errorMsg: 'unsupported operand type' },
    // Test for overflow: using a large finite value that causes Math.exp(x) to be Infinity
    { input: 710, errorMsg: 'overflow' }
  ];
  errorExpCases.forEach(({ input, errorMsg }) => {
    it(`should throw error "${errorMsg}" for exp(${input})`, () => {
      assert.throws(() => calc.exp(input), new Error(errorMsg));
    });
  });
});

describe('Calculator.log', () => {
  const calc = new Calculator();

  // Non-error test cases (at least 3)
  const validLogCases = [
    { input: 1, expected: Math.log(1) },          // log(1) = 0
    { input: Math.E, expected: Math.log(Math.E) },  // log(e) = 1
    { input: 10, expected: Math.log(10) }           // log(10) ≈ 2.30259
  ];
  validLogCases.forEach(({ input, expected }) => {
    it(`should return ${expected} for log(${input})`, () => {
      const result = calc.log(input);
      // Use a tolerance for floating-point comparisons
      assert.ok(Math.abs(result - expected) < 1e-10);
    });
  });

  // Error test cases (parameterized)
  const errorLogCases = [
    { input: Infinity, errorMsg: 'unsupported operand type' },
    { input: -Infinity, errorMsg: 'unsupported operand type' },
    { input: NaN, errorMsg: 'unsupported operand type' },
    { input: 0, errorMsg: 'math domain error (1)' },  // log(0) results in -Infinity
    { input: -1, errorMsg: 'math domain error (2)' }  // log(-1) results in NaN
  ];
  errorLogCases.forEach(({ input, errorMsg }) => {
    it(`should throw error "${errorMsg}" for log(${input})`, () => {
      assert.throws(() => calc.log(input), new Error(errorMsg));
    });
  });
});

