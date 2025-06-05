const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

// test('Test function Calculator.exp()
describe('Test Calculator.exp()', () => {
    it('Should return result successfully for valid input and finite output', () => {
        const calculator = new Calculator()
        const testCases = [
            { input: 0, expected: 1 },
            { input: 1, expected: Math.E },
            { input: 2, expected: Math.exp(2) },
            { input: -1, expected: 1 / Math.E },
            { input: -2, expected: Math.exp(-2) }
        ]

        testCases.forEach(({ input, expected }) => {
            assert.strictEqual(calculator.exp(input), expected);
        })
    })
    
    it('Should raise unsupported operand type error for invalid input', () => {
        const calculator = new Calculator();
        const testCases = [NaN, Infinity, -Infinity]
        const expected = /^Error: unsupported operand type$/;

        testCases.forEach(({ input }) => {
            assert.throws(() => calculator.exp(input), expected);
        })
    })
    
    it('Should raise overflow error for overflow result', () => {
        const calculator = new Calculator();
        const input = 1000;
        const expected = /^Error: overflow$/;

        assert.throws(() => calculator.exp(input), expected)
    })
})

// test('Test function Calculator.log()
describe('Test Calculator.log()', () => {
    it('Should return result successfully for valid input and finite output', () => {
        const calculator = new Calculator();
        const testCases = [
            { input: 1, expected: 0 },
            { input: Math.E, expected: 1 },
            { input: Math.exp(2), expected: 2 }
        ]

        testCases.forEach(({ input, expected }) => {
            assert.strictEqual(calculator.log(input), expected);
        })
    })

    it('Should raise unsupported operand type error for invalid input', () => {
        const calculator = new Calculator();
        const testCases = [NaN, Infinity, -Infinity]
        const expected = /^Error: unsupported operand type$/;

        testCases.forEach(({ input }) => {
            assert.throws(() => calculator.log(input), expected);
        })
    })

    it('Should throw domain error for log of non-positive number', () => {
        const calculator = new Calculator();
        testCases = [
            { input: 0, expected: /^Error: math domain error \(1\)$/ },
            { input: -1, expected: /^Error: math domain error \(2\)$/ }
        ]

        testCases.forEach(({ input, expected }) => {
            assert.throws(() => calculator.log(input), expected);
        })
    })
})