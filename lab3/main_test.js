const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
    const calc = new Calculator();

    // ---- exp(x) tests ----
    it('exp(0) should return 1', () => {
        assert.strictEqual(calc.exp(0), 1);
    });

    it('exp(1) should return ~2.718', () => {
        assert.ok(Math.abs(calc.exp(1) - Math.E) < 1e-10);
    });

    it('exp(Infinity) should throw unsupported operand type', () => {
        assert.throws(() => calc.exp(Infinity), {
            message: 'unsupported operand type'
        });
    });

    it('exp(1000) should throw overflow', () => {
        assert.throws(() => calc.exp(1000), {
            message: 'overflow'
        });
    });

    // ---- log(x) tests ----
    it('log(1) should return 0', () => {
        assert.strictEqual(calc.log(1), 0);
    });

    it('log(0) should throw math domain error (1)', () => {
        assert.throws(() => calc.log(0), {
            message: 'math domain error (1)'
        });
    });

    it('log(-5) should throw math domain error (2)', () => {
        assert.throws(() => calc.log(-5), {
            message: 'math domain error (2)'
        });
    });

    it('log(NaN) should throw unsupported operand type', () => {
        assert.throws(() => calc.log(NaN), {
            message: 'unsupported operand type'
        });
    });
});
