const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('Calculator', () => {
    it('should calculate exp correctly', () => {
        const calculator = new Calculator();
        const infiniteValue = Infinity;
        assert.throws(() => calculator.exp(infiniteValue), Error);
        assert.throws(() => calculator.exp(Number.MAX_VALUE), Error);
        assert.strictEqual(calculator.exp(1), Math.exp(1));
    });

    it('should calculate log correctly', () => {
        const calculator = new Calculator();
        const infiniteValue = Infinity;
        assert.throws(() => calculator.log(infiniteValue), Error);
        assert.strictEqual(calculator.log(2), Math.log(2));
        assert.throws(() => calculator.log(0), Error);
        assert.throws(() => calculator.log(-1), Error);
    });
});