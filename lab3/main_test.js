const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('Parameterization', () => {
    it('exp', () => {
        const testcases = [
            {param: 0, expected: 1},
            {param: 1, expected: 2.718281828459045},
            {param: -1, expected: 0.36787944117144233},
            {param: 5, expected: 148.4131591025766},
            {param: 10, expected: 22026.465794806718}
        ];
        const calculator = new Calculator();
        for (const tc of testcases) {
            assert.strictEqual(calculator.exp(tc.param), tc.expected);
        }
    });
    it('log', () => {
        const testcases = [
            {param: 1, expected: 0},
            {param: 10, expected: 2.302585092994046},
            {param: 8, expected: 2.0794415416798357},
            {param: 90, expected: 4.499809670330265},
            {param: Math.E, expected: 1}
        ];
        const calculator = new Calculator();
        for (const tc of testcases) {
            assert.strictEqual(calculator.log(tc.param), tc.expected);
        }
    });
})

var infinite_number = 1 / 0;
var calculator = new Calculator();

describe('Errors', () => {
    it('exp infinite number', () => {
        assert.throws(function () {calculator.exp(infinite_number)});
    });
    it('exp overflow', () => {
        cause = 999999999;
        assert.throws(function() {calculator.exp(cause)});
    });
    it('log infinite number', () => {
        assert.throws(function() {calculator.log(infinite_number)});
    });
    it('log math domain error (1)', () => {
        assert.throws(function() {calculator.log(0)});
    })
    it('log math domain error (2)', () => {
        assert.throws(function() {calculator.log(-234)})
    })
})