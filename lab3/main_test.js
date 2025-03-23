const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    const calculator = new Calculator();

    describe('exp()', () => {
        it('should return correct exponential values', () => {
            assert.strictEqual(calculator.exp(1), Math.exp(1));
            assert.strictEqual(calculator.exp(0), Math.exp(0)); // exp(0) = 1
            assert.strictEqual(calculator.exp(-1), Math.exp(-1));
        });

        it('should throw error for non-finite values', () => {
            assert.throws(() => calculator.exp(Infinity), /unsupported operand type/);
            assert.throws(() => calculator.exp(NaN), /unsupported operand type/);
            assert.throws(() => calculator.exp(undefined), /unsupported operand type/);
            assert.throws(() => calculator.exp(null), /unsupported operand type/);
        });

        it('should throw error on overflow', () => {
            assert.throws(() => calculator.exp(1000), /overflow/);
        });
    });

    describe('log()', () => {
        it('should return correct logarithm values', () => {
            assert.strictEqual(calculator.log(1), Math.log(1)); // log(1) = 0
            assert.strictEqual(calculator.log(Math.E), Math.log(Math.E)); // log(e) = 1
            assert.strictEqual(calculator.log(10), Math.log(10));
        });

        it('should throw error for zero values', () => {
            assert.throws(() => calculator.log(0), /math domain error \(1\)/);
        });

        it('should throw error for negative values', () => {
            assert.throws(() => calculator.log(-1), /math domain error \(2\)/);
        });

        it('should throw error for NaN', () => {
            assert.throws(() => calculator.log(NaN), /unsupported operand type/); // ✅ 修正這裡
        });

        it('should throw error for non-numeric inputs', () => {
            assert.throws(() => calculator.log(Infinity), /unsupported operand type/);
            assert.throws(() => calculator.log(undefined), /unsupported operand type/);
            assert.throws(() => calculator.log(null), /unsupported operand type/);
        });
    });
});
