const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');
const test = require('node:test');
// TODO: write your tests here
// const { test, describe } = require('node:test');
// const assert = require('assert');
// const { Calculator } = require('./main');

describe('Calculator', () => {
    const calculator = new Calculator();

    test('return Math.exp(x) ',  () => {
        assert.ok(Math.abs(calculator.exp(1) - Math.exp(1)) < 1e-10);
        assert.ok(Math.abs(calculator.exp(0) - 1) < 1e-10);
    });

    test('exp() throw "unsupported operand type" for non-finite x', () => {
        assert.throws(() => calculator.exp(Infinity), /unsupported operand type/);
        assert.throws(() => calculator.exp(-Infinity), /unsupported operand type/);
        assert.throws(() => calculator.exp(NaN), /unsupported operand type/);
    });

    test('exp() throw "overflow" for large x resulting Infinity',  () => {
        assert.throws(() => calculator.exp(10000), /overflow/);
    });

    test('log() return Math.log(x) ',  () => {
        assert.ok(Math.abs(calculator.log(1) - 0) < 1e-10);
        assert.ok(Math.abs(calculator.log(Math.E) - 1) < 1e-10);
    });

    test('log() throw "unsupported operand type" for non-finite x',  () => {
        assert.throws(() => calculator.log(Infinity), /unsupported operand type/);
        assert.throws(() => calculator.log(-Infinity), /unsupported operand type/);
        assert.throws(() => calculator.log(NaN), /unsupported operand type/);
    });

    test('log() throw "math domain error (1)" when x = 0',  () => {
        assert.throws(() => calculator.log(0), /math domain error \(1\)/);
    });

    test('log() throw "math domain error (2)" when x < 0',  () => {
        assert.throws(() => calculator.log(-1), /math domain error \(2\)/);
    });
});
