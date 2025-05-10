const { describe, it } = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator Functionality', () => {
    it('check exp method', () => {
        const testCases = [
            { input: 2, expected: 7.38905609893065 },
            { input: 5, expected: 148.4131591025766 },
            { input: 10, expected: 22026.465794806718 },
            { input: -1, expected: 0.36787944117144233 },
            { input: -5, expected: 0.006737946999085467 },
            { input: 0, expected: 1 }
        ];
        const calculator = new Calculator();
        testCases.forEach(({ input, expected }) => {
            const result = calculator.exp(input);
            assert.strictEqual(result, expected);
        });
    });

    it('check log method', () => {
        const testCases = [
            { input: 2, expected: 0.6931471805599453 },
            { input: 5, expected: 1.6094379124341003 },
            { input: 10, expected: 2.302585092994046 },
            { input: Math.E, expected: 1 },
            { input: Math.E * Math.E, expected: 2 },
            { input: Math.E * Math.E * Math.E, expected: 3 }
        ];
        const calculator = new Calculator();
        testCases.forEach(({ input, expected }) => {
            const result = calculator.log(input);
            assert.strictEqual(result, expected);
        });
    });
}
);

describe('Calculator Error Handling', () => {
    it('check exp handle non-finite numbers', () => {
        const testCases = [
            { input: NaN, expected: 'unsupported operand type' },
            { input: Infinity, expected: 'unsupported operand type' },
            { input: -Infinity, expected: 'unsupported operand type' }
        ];
        const calculator = new Calculator();
        testCases.forEach(({ input, expected }) => {
            assert.throws(() => {
                calculator.exp(input);
            }, {
                name: 'Error',
                message: expected
            });
        });
    });

    it('check exp handle overflow', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.exp(1000);
        }, {
            name: 'Error',
            message: 'overflow'
        });
    }
    );

    it('check log handle non-finite numbers', () => {
        const testCases = [
            { input: NaN, expected: 'unsupported operand type' },
            { input: Infinity, expected: 'unsupported operand type' },
            { input: -Infinity, expected: 'unsupported operand type' }
        ];
        const calculator = new Calculator();
        testCases.forEach(({ input, expected }) => {
            assert.throws(() => {
                calculator.log(input);
            }, {
                name: 'Error',
                message: expected
            });
        });
    });

    it('check log handle 0', () => {
        const calculator = new Calculator();
        assert.throws(() => {
            calculator.log(0);
        }, {
            name: 'Error',
            message: 'math domain error (1)'
        });
    }
    );

    it('check log handle negative number', () => {
        const testCases = [
            { input: -1, expected: 'math domain error (2)' },
            { input: -2, expected: 'math domain error (2)' },
            { input: -Math.E, expected: 'math domain error (2)' }
        ];
        const calculator = new Calculator();
        testCases.forEach(({ input, expected }) => {
            assert.throws(() => {
                calculator.log(input);
            }, {
                name: 'Error',
                message: expected
            });
        });
    });
});
