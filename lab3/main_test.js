const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
// 測試 exp 方法
describe('exp()', () => {
    it('should return the correct result for finite input', () => {
        const calculator = new Calculator();
        const result = calculator.exp(1);
        assert.strictEqual(result, Math.exp(1));
    });

    it('should throw an error for non-finite input', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.exp(Infinity);
        }, /unsupported operand type/);

        assert.throws(() => {
            calculator.exp(NaN);
        }, /unsupported operand type/);
    });

    it('should throw an error for overflow', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.exp(710);
        }, /overflow/);
    });
});

// 測試 log 方法
describe('log()', () => {
    it('should return the correct result for finite input', () => {
        const calculator = new Calculator();
        const result = calculator.log(10);
        assert.strictEqual(result, Math.log(10));
    });

    it('should throw an error for non-finite input', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.log(Infinity);
        }, /unsupported operand type/);

        assert.throws(() => {
            calculator.log(NaN);
        }, /unsupported operand type/);
    });

    it('should throw an error for log of non-positive number', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.log(0);  // Log of 0 is -Infinity
        }, /math domain error \(1\)/);

        assert.throws(() => {
            calculator.log(-1);  // Log of negative number is NaN
        }, /math domain error \(2\)/);
    });
});
