const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
  describe('exp', () => {
    it('Test Math.exp(x) for normal finite x', () => {
      const calc = new Calculator();
      const result = calc.exp(10);
      assert.strictEqual(result, Math.exp(10));
    });

    it('Test if x is not finite (Infinity / NaN)', () => {
      const calc = new Calculator();
      assert.throws(() => calc.exp(Infinity), /unsupported operand type/);
      assert.throws(() => calc.exp(NaN), /unsupported operand type/);
    });

    it('Test if Math.exp(x) is Infinity (very large x)', () => {
      const calc = new Calculator();
      assert.throws(() => calc.exp(1e100), /overflow/);
    });
  });

  describe('log', () => {
    it('Test Math.log(x) for normal positive x', () => {
      const calc = new Calculator();
      const result = calc.log(10);
      assert.strictEqual(result, Math.log(10));
    });

    it('Test if x is not finite (Infinity / NaN)', () => {
      const calc = new Calculator();
      assert.throws(() => calc.log(Infinity), /unsupported operand type/);
      assert.throws(() => calc.log(NaN), /unsupported operand type/);
    });

    it('Test if Math.log(x) = -Infinity (x=0)', () => {
      const calc = new Calculator();
      assert.throws(() => calc.log(0), /math domain error \(1\)/);
    });

    it('Test if Math.log(x) = NaN (x < 0)', () => {
      const calc = new Calculator();
      assert.throws(() => calc.log(-1), /math domain error \(2\)/);
    });
  });
});
