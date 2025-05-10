const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
  const calculator = new Calculator();

  describe('exp()', () => {
    describe('Error Cases', () => {
      // 錯誤案例：非有限數值
      const errorCases = [
        { input: Infinity, error: 'unsupported operand type' },
        { input: -Infinity, error: 'unsupported operand type' },
        { input: NaN, error: 'unsupported operand type' },
        // 大數導致結果溢出：Math.exp(1000) === Infinity
        { input: 1000, error: 'overflow' }
      ];
      
      errorCases.forEach(({ input, error }) => {
        it(`should throw error "${error}" for input ${input}`, () => {
          assert.throws(() => { calculator.exp(input); }, { message: error });
        });
      });
    });

    describe('Non-Error Cases', () => {
      // 非錯誤案例：正常運算
      const nonErrorCases = [
        { input: 0, expected: Math.exp(0) },
        { input: 1, expected: Math.exp(1) },
        { input: -1, expected: Math.exp(-1) }
      ];
      
      nonErrorCases.forEach(({ input, expected }) => {
        it(`should return ${expected} for input ${input}`, () => {
          const result = calculator.exp(input);
          assert.strictEqual(result, expected);
        });
      });
    });
  });

  describe('log()', () => {
    describe('Error Cases', () => {
      // 錯誤案例：
      // 若 x 為非有限數值則拋出 'unsupported operand type'
      // 若 x = 0 則 Math.log(0) === -Infinity 拋出 'math domain error (1)'
      // 若 x 為負數則 Math.log(x) === NaN 拋出 'math domain error (2)'
      const errorCases = [
        { input: Infinity, error: 'unsupported operand type' },
        { input: -Infinity, error: 'unsupported operand type' },
        { input: NaN, error: 'unsupported operand type' },
        { input: 0, error: 'math domain error (1)' },
        { input: -1, error: 'math domain error (2)' }
      ];
      
      errorCases.forEach(({ input, error }) => {
        it(`should throw error "${error}" for input ${input}`, () => {
          assert.throws(() => { calculator.log(input); }, { message: error });
        });
      });
    });

    describe('Non-Error Cases', () => {
      // 非錯誤案例：正數
      const nonErrorCases = [
        { input: 1, expected: Math.log(1) },
        { input: 10, expected: Math.log(10) },
        { input: Math.E, expected: 1 }
      ];
      
      nonErrorCases.forEach(({ input, expected }) => {
        it(`should return ${expected} for input ${input}`, () => {
          const result = calculator.log(input);
          assert.strictEqual(result, expected);
        });
      });
    });
  });
});
