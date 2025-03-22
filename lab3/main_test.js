const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    let calculator;
    beforeEach(() => {
        calculator = new Calculator();
    });

    describe('exp method', () => {
        it('unsupported operand type', () => {
            const testcases = [
                { param: [Infinity], expected: 'unsupported operand type' },
                { param: [-Infinity], expected: 'unsupported operand type' },
                { param: [NaN], expected: 'unsupported operand type' },
            ];

            for (const tc of testcases) {
                assert.throws(() => calculator.exp(...tc.param), new RegExp(tc.expected));
            }
        });

        it('overflow', () => {
            const testcases = [
                { param: [710], expected: 'overflow' },
            ];

            for (const tc of testcases) {
                assert.throws(() => calculator.exp(...tc.param), new RegExp(tc.expected));
            }
        });

        it('normal', () => {
            const testcases = [
                { param: [0], expected: Math.exp(0) },
                { param: [1], expected: Math.exp(1) },
                { param: [2], expected: Math.exp(2) },
                { param: [-1], expected: Math.exp(-1) },
                { param: [-2], expected: Math.exp(-2) },
            ];

            for (const tc of testcases) {
                const result = calculator.exp(...tc.param);
                assert.strictEqual(result, tc.expected);
            }
        });
    });

    describe('log method', () => {
        it('unsupported operand type', () => {
            const testcases = [
                { param: [Infinity], expected: 'unsupported operand type' },
                { param: [-Infinity], expected: 'unsupported operand type' },
                { param: [NaN], expected: 'unsupported operand type' },
            ];

            for (const tc of testcases) {
                assert.throws(() => calculator.log(...tc.param), new RegExp(tc.expected));
            }
        });

        it('math domain error (1)', () => {
            const testcases = [
                { param: [0], expected: 'math domain error \\(1\\)' },
            ];

            for (const tc of testcases) {
                assert.throws(() => calculator.log(...tc.param), new RegExp(tc.expected));
            }
        });

        it('math domain error (2)', () => {
            const testcases = [
                { param: [-1], expected: 'math domain error \\(2\\)' },
                { param: [-2], expected: 'math domain error \\(2\\)' },
            ];

            for (const tc of testcases) {
                assert.throws(() => calculator.log(...tc.param), new RegExp(tc.expected));
            }
        });

        it('normal', () => {
            const testcases = [
                { param: [1], expected: Math.log(1) },
                { param: [2], expected: Math.log(2) },
            ];

            for (const tc of testcases) {
                const result = calculator.log(...tc.param);
                assert.strictEqual(result, tc.expected);
            }
        });
    });
});
