const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
describe('Caculator', () => {
    const calculator = new Calculator();

    const testCases = [
        { method: 'exp', input: 0, expected: 1 },
        { method: 'exp', input: 1, expected: Math.exp(1) },
        { method: 'log', input: 1, expected: 0 },
        { method: 'log', input: 10, expected: Math.log(10) },
    ];

    testCases.forEach(({ method, input, expected }) => {
        it(`should return ${expected} for ${method}(${input})`, () => {
            assert.strictEqual(calculator[method](input), expected);
        });
    });

    const errorCases = [
        { method: 'exp', input: Infinity, error: 'unsupported operand type' },
        { method: 'exp', input: 1000, error: 'overflow' },
        { method: 'log', input: Infinity, error: 'unsupported operand type' },
        { method: 'log', input: 0, error: /math domain error \(1\)/ },
        { method: 'log', input: -1, error: /math domain error \(2\)/ },
    ];

    errorCases.forEach(({ method, input, error }) => {
        it(`should throw "${error}" for ${method}(${input})`, () => {
            assert.throws(() => calculator[method](input), new RegExp(error));
        });
    });
});

