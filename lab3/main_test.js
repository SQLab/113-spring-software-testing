const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe('Calculator', () => {
    
    it('should calculate exp correctly', () => {
        const testcases = [
            [Infinity, 'unsupported operand type'],
            [Number.MAX_VALUE, 'overflow'],
            [1, Math.exp(1)],
            [0, Math.exp(0)],
            [-1, Math.exp(-1)]
        ];
        const calculator = new Calculator();
        for (const [input, expected] of testcases) {
            if (typeof expected === 'string') {
                assert.throws(() => calculator.exp(input), Error);
            } else {
                assert.strictEqual(calculator.exp(input), expected);
            }
        }
    });

    it('should calculate log correctly', () => {
        const testcases = [
            [Infinity, 'unsupported operand type'],
            [0, 'unsupported operand type'],
            [-1, 'unsupported operand type'],
            [1, Math.log(1)],
            [100, Math.log(100)],
            [Math.E, Math.log(Math.E)]
        ];
        const calculator = new Calculator();
        for (const [input, expected] of testcases) {
            if (typeof expected === 'string') {
                assert.throws(() => calculator.log(input), Error);
            } else {
                assert.strictEqual(calculator.log(input), expected);
            }
        }
    });
});

