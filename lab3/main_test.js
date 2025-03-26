// const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');
const test = require('node:test');
// TODO: write your tests here

const calc = new Calculator();
test('exp', () => {
    const cases = [
        { input: 1, expected: Math.exp(1) },
        { input: 0, expected: 1 },
        { input: -2, expected: Math.exp(-2) }
    ];

    for (const tc of cases) {
        assert.ok(Math.abs(calc.exp(tc.input) - tc.expected) < 1e-10);
    }
});


test('log', () => {
    const cases = [
        { input: 1, expected: 0 },
        { input: Math.E, expected: 1 },
        { input: 10, expected: Math.log(10) }
    ];

    for (const tc of cases) {
        assert.ok(Math.abs(calc.log(tc.input) - tc.expected) < 1e-10);
    }
});

// error
test('exp type error or overflow', () => {
    const badInputs = [Infinity, -Infinity, NaN];
    for (const val of badInputs) {
        assert.throws(() => calc.exp(val), /unsupported operand type/);
    }

    assert.throws(() => calc.exp(10000), /overflow/);
});

test('log errors', () => {
    const badInputs = [Infinity, -Infinity, NaN];
    for (const val of badInputs) {
        assert.throws(() => calc.log(val), /unsupported operand type/);
    }

    assert.throws(() => calc.log(0), /math domain error \(1\)/);
    assert.throws(() => calc.log(-1), /math domain error \(2\)/);
});