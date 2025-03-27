const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe('Calculator', () => {
    describe('testing exp(x) method', () => {
      it('Normal finite x as argument', () => {
        const calc = new Calculator();
        const result = calc.exp(5);
        assert.strictEqual(result, Math.exp(5));
      });
  
      it('Throws when undefined as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(undefined), /unsupported operand type/);
      });
      
      it('Throws when string as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp("5"), /unsupported operand type/);
      });
      
      it('Throws when null input as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(null), /unsupported operand type/);
      });
      
      it('Throws when infinite x or NaN as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(Infinity), /unsupported operand type/);
        assert.throws(() => calc.exp(NaN), /unsupported operand type/);
      });

      it('Throws when -infinity x as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(-Infinity), /unsupported operand type/);
      });
  
      it('Throws for overflow argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.exp(10000), /overflow/);
      });
    });
  
    describe('testing log(x) method', () => {
      it('Normal finite x as argument', () => {
        const calc = new Calculator();
        const result = calc.log(10);
        assert.strictEqual(result, Math.log(10));
      });

      it('Throws when string as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log("5"), /unsupported operand type/);
      });
  
      it('Throws when infinite x or NaN as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(Infinity), /unsupported operand type/);
        assert.throws(() => calc.log(NaN), /unsupported operand type/);
      });
      
      it('Throws when null input as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(null), /unsupported operand type/);
      });
      
      it('Throws when undefined as argument', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(undefined), /unsupported operand type/);
      });
  
      it('Throws when x = 0, becomes inf (math domain error 1)', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(0), /math domain error \(1\)/);
      });
  
      it('Throws when x < 0 (math domain error 2)', () => {
        const calc = new Calculator();
        assert.throws(() => calc.log(-1), /math domain error \(2\)/);
      });
    });
  });