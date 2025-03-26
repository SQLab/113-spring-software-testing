const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    const calculator = new Calculator();

    describe('exp()', () => {
        it('should return correct exponentiation results', () => {
            assert.strictEqual(calculator.exp(0), 1);
            assert.strictEqual(calculator.exp(1), Math.exp(1));
            assert.strictEqual(calculator.exp(-1), Math.exp(-1));
            assert.strictEqual(calculator.exp(5), Math.exp(5));
        });

        it('should throw an error for non-finite numbers', () => {
            assert.throws(() => calculator.exp(Infinity), /unsupported operand type/);
            assert.throws(() => calculator.exp(-Infinity), /unsupported operand type/);
            assert.throws(() => calculator.exp(NaN), /unsupported operand type/);
        });

        it('should throw an overflow error for large numbers', () => {
            assert.throws(() => calculator.exp(1000), /overflow/);
        });
    });
});
