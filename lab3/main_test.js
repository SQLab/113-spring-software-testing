const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator Functions', () => {
  describe('Exponentiation (exp)', () => {
    const expCases = [
      { value: 0, result: 1, desc: 'exp(0)' },
      { value: 1, result: Math.E, desc: 'exp(1)' },
      { value: 2, result: Math.exp(2), desc: 'exp(2)' },
      { value: -1, result: 1 / Math.E, desc: 'exp(-1)' },
      { value: -2, result: Math.exp(-2), desc: 'exp(-2)' }
    ];

    expCases.forEach(({ value, result, desc }) => {
      it(`should return correct value for ${desc}`, () => {
        const calc = new Calculator();
        assert.strictEqual(calc.exp(value), result);
      });
    });

    const expErrorCases = [
      { value: Infinity, errMsg: 'unsupported operand type', desc: 'exp(Infinity)' },
      { value: -Infinity, errMsg: 'unsupported operand type', desc: 'exp(-Infinity)' },
      { value: NaN, errMsg: 'unsupported operand type', desc: 'exp(NaN)' },
      { value: 1000, errMsg: 'overflow', desc: 'exp(large number)' }
    ];

    expErrorCases.forEach(({ value, errMsg, desc }) => {
      it(`should throw an error for ${desc}`, () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(value), {
          name: 'Error',
          message: errMsg
        });
      });
    });
  });

  describe('Natural Logarithm (log)', () => {
    const logCases = [
      { value: 1, result: 0, desc: 'ln(1)' },
      { value: Math.E, result: 1, desc: 'ln(e)' },
      { value: Math.exp(2), result: 2, desc: 'ln(e^2)' }
    ];

    logCases.forEach(({ value, result, desc }) => {
      it(`should return correct value for ${desc}`, () => {
        const calc = new Calculator();
        assert.strictEqual(calc.log(value), result);
      });
    });

    const logErrorCases = [
      { value: -1, errMsg: 'math domain error (2)', desc: 'ln(negative)' },
      { value: 0, errMsg: 'math domain error (1)', desc: 'ln(0)' },
      { value: Infinity, errMsg: 'unsupported operand type', desc: 'ln(Infinity)' },
      { value: -Infinity, errMsg: 'unsupported operand type', desc: 'ln(-Infinity)' },
      { value: NaN, errMsg: 'unsupported operand type', desc: 'ln(NaN)' }
    ];

    logErrorCases.forEach(({ value, errMsg, desc }) => {
      it(`should throw an error for ${desc}`, () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(value), {
          name: 'Error',
          message: errMsg
        });
      });
    });
  });
});