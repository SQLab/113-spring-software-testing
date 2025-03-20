
const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('Calculator', () => {
    const calculator = new Calculator();
    
    describe('exp', () => {
        it('exp should throw error for Infinity input', () => {
            assert.throws(
                () => calculator.exp(Infinity), 
                { message: 'unsupported operand type' }, 
                'exp(Infinity) should throw "unsupported operand type"'
            );
        });
    
        it('exp should throw overflow error for extremely large input', () => {
            assert.throws(
                () => calculator.exp(48763), // 48763 is the limit before Math.exp() returns Infinity
                { message: 'overflow' },
                'exp(48763) should throw "overflow" due to exceeding the limit'
            );
        });
    
        it('exp should return correct result for valid input', () => {
            assert.equal(calculator.exp(1), Math.exp(1), 'exp(1) should return Math.exp(1)');
            assert.equal(calculator.exp(0), Math.exp(0), 'exp(0) should return Math.exp(0)');
        });
    });

    describe('log', () => {
        it('log should throw error for Infinity input', () => {
            assert.throws(
                () => calculator.log(Infinity), 
                { message: 'unsupported operand type' }, 
                'log(Infinity) should throw "unsupported operand type"'
            );
        });
        it('log should throw math domain error for 0 input', () => {
            assert.throws(
                () => calculator.log(0),
                { message: 'math domain error (1)' },
                'log(0) should throw "math domain error (1)"'
            );
        });
        it('log should throw math domain error for negative input', () => {
            assert.throws(
                () => calculator.log(-1),
                { message: 'math domain error (2)' },
                'log(-1) should throw "math domain error (2)"'
            );
        });
        it('log should return correct result for valid input', () => {
            assert.equal(calculator.log(Math.E), 1, 'log(Math.E) should return 1');
            assert.equal(calculator.log(1), 0, 'log(1) should return 0');
            assert.equal(calculator.log(10), Math.log(10), 'log(10) should return Math.log(10)');
        });
    });

});