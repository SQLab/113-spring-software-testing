const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

const calc = new Calculator();

describe('Calculator', () => {
    // exp() 正確結果
    it('exp() should return correct results', () => {
        const cases = [
            { param: 0, expected: Math.exp(0) },
            { param: 1, expected: Math.exp(1) },
            { param: -1, expected: Math.exp(-1) },
        ];
        for (const c of cases) {
            assert.strictEqual(calc.exp(c.param), c.expected);
        }
    });

    // exp() 錯誤處理 unsupported operand
    it('exp() should throw unsupported operand type', () => {
        const inputs = [Infinity, -Infinity, NaN];
        for (const x of inputs) {
            assert.throws(() => calc.exp(x), { message: 'unsupported operand type' });
        }
    });

    // exp() overflow
    it('exp() should throw overflow for large number', () => {
        assert.throws(() => calc.exp(1000), { message: 'overflow' });
    });

    // log() 正確結果
    it('log() should return correct results', () => {
        const cases = [
            { param: 1, expected: Math.log(1) },
            { param: Math.E, expected: Math.log(Math.E) },
            { param: 10, expected: Math.log(10) },
        ];
        for (const c of cases) {
            assert.strictEqual(calc.log(c.param), c.expected);
        }
    });

    // log() 錯誤處理 unsupported operand
    it('log() should throw unsupported operand type', () => {
        const inputs = [Infinity, -Infinity, NaN];
        for (const x of inputs) {
            assert.throws(() => calc.log(x), { message: 'unsupported operand type' });
        }
    });

    // log() math domain error (1)
    it('log() should throw math domain error (1) for 0', () => {
        assert.throws(() => calc.log(0), { message: 'math domain error (1)' });
    });

    // log() math domain error (2)
    it('log() should throw math domain error (2) for negative input', () => {
        assert.throws(() => calc.log(-3), { message: 'math domain error (2)' });
    });
});
