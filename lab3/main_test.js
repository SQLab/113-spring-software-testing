const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe("test Calculator", () => {
    const calculator = new Calculator;
    // console.log(calculator.exp(1000000000));
    describe("exp(x) testing", () => {
        it("error testcases", () => {
            const testcases = [
                { param: [Infinity], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: [-Infinity], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: ['abc'], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: [1234567890], expected: {
                    name: 'Error',
                    message: 'overflow'
                } }
            ];
            for (tc of testcases) {
                assert.throws(() => {
                    calculator.exp.apply(this, tc.param)},
                    tc.expected
                );
            }
        });

/*        it("isFinite Error", () => {
            assert.throws(() => {
                calculator.exp(Infinity);
            }, {
                name: 'Error',
                message: 'unsupported operand type'
            });
            assert.throws(() => {
                calculator.exp('abc');
            }, {
                name: 'Error',
                message: 'unsupported operand type'
            });
        });
        it("overflow Error", () => {
            assert.throws(() => {
                calculator.exp(1000000000);
            }, {
                name: 'Error',
                message: 'overflow'
            });
        });
*/
        it("normal behavior", () => {
            const testcases = [
                { param: [1], expected: Math.exp(1) },
                { param: [16], expected: Math.exp(16) },
                { param: [-3], expected: Math.exp(-3) },
                { param: [0.794], expected: Math.exp(0.794) }
            ];
            for (const tc of testcases) {
                assert.strictEqual(calculator.exp.apply(this, tc.param), tc.expected);
            }
        });
    });
    describe("log(x) testing", () => {
        it("error testcases", () => {
            const testcases = [
                { param: [Infinity], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: [-Infinity], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: ['abc'], expected: {
                    name: 'Error',
                    message: 'unsupported operand type'
                } },
                { param: [0], expected: {
                    name: 'Error',
                    message: 'math domain error (1)'
                } },
                { param: [-1], expected: {
                    name: 'Error',
                    message: 'math domain error (2)'
                } },
                { param: [-1000000], expected: {
                    name: 'Error',
                    message: 'math domain error (2)'
                } }
            ];
            for (tc of testcases) {
                assert.throws(() => {
                    calculator.log.apply(this, tc.param)},
                    tc.expected
                );
            }
        });

/*        it("isFinite Error", () =>{
            assert.throws(() => {
                calculator.log(Infinity);
            }, {
                name: 'Error',
                message: 'unsupported operand type'
            });
            assert.throws(() => {
                calculator.log('abc');
            }, {
                name: 'Error',
                message: 'unsupported operand type'
            });
        });
        it("domain error (1)", () => {
            assert.throws(() => {
                calculator.log(0);
            }, {
                name: 'Error',
                message: 'math domain error (1)'
            });
        });
        it("domain error (2)", () => {
            assert.throws(() => {
                calculator.log(-1);
            }, {
                name: 'Error',
                message: 'math domain error (2)'
            });
            assert.throws(() => {
                calculator.log(-1000000);
            }, {
                name: 'Error',
                message: 'math domain error (2)'
            });
        });
*/
        it("normal behavior", () => {
            const testcases = [
                { param: [1], expected: Math.log(1) },
                { param: [16], expected: Math.log(16) },
                { param: [3456789], expected: Math.log(3456789) },
                { param: [0.794], expected: Math.log(0.794) }
            ];
            for (const tc of testcases) {
                assert.strictEqual(calculator.log.apply(this, tc.param), tc.expected);
            }
        });
    });
});