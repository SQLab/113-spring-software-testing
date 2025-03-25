const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');
const { normalize } = require('path');

describe('Calculator', () =>{
    const calculator = new Calculator();

    describe('exp(x)', () =>{
        const normalCases = [
            {x: 0, expected: 1},
            {x: 1, expected: Math.E},
            {x: -1, expected: 1/Math.E}
        ];

        for(const nc of normalCases)
        {
            assert.strictEqual(calculator.exp(nc.x), nc.expected);
        }

        const errorCases = [
            {x: Infinity, error: 'unsupported operand type'},
            {x: NaN, error: 'unsupported operand type'},
            {x: 10000, error: 'overflow'},

        ];

        for(const ec of errorCases)
        {
            assert.throws(() => {calculator.exp(ec.x);}, { message: ec.error});
        }
    });

    describe('log(x)', () =>{
        const normalCases = [
            {x: 1, expected: 0},
            {x: Math.E, expected: 1},
            {x: 1/Math.E, expected: -1}
        ];

        for(const nc of normalCases)
        {
            assert.strictEqual(calculator.log(nc.x), nc.expected);
        }

        const errorCases = [
            {x: Infinity, error: 'unsupported operand type'},
            {x: NaN, error: 'unsupported operand type'},
            {x: 0, error: 'math domain error (1)'},
            {x: -1, error: 'math domain error (2)'}

        ];

        for(const ec of errorCases)
        {
            assert.throws(() => {calculator.log(ec.x);}, { message: ec.error});
        }
    });
});
