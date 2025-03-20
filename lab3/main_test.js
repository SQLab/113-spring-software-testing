const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here

describe('Calculator', () => {
    it("Test calculator's exp()", () => {
        const calculator = new Calculator();
        const testcase = [
          {
            parameter: Infinity,
            expected: Error,
            MessageErr: "unsupported operand type",
          },
          {
            parameter: Number.MAX_VALUE,
            expected: Error,
            MessageErr: "overflow",
          },
          {
            parameter: 0,
            expected: Math.exp(0),
          },
          {
            parameter: 1,
            expected: Math.exp(1),
          },
          {
            parameter: 2,
            expected: Math.exp(2),
          }
        ];
        for (const { parameter, expected, MessageErr } of testcase){
          if (expected == Error) {
            assert.throws(() => calculator.exp(parameter), Error(MessageErr));
          } else {
            assert.strictEqual(calculator.exp(parameter), expected);
          }
        };
      });
      it("Test calculator's log()", () => {
        const calculator = new Calculator();
        const testcase = [
          {
            parameter: Infinity,
            expected: Error,
            MessageErr: "unsupported operand type",
          },
          {
            parameter: 0,
            expected: Error,
            MessageErr: "math domain error (1)",
          },
          {
            parameter: -1,
            expected: Error,
            MessageErr: "math domain error (2)",
          },
          {
            parameter: 2,
            expected: Math.log(2),
          },
          {
            parameter: 3,
            expected: Math.log(3),
          },
          {
            parameter: 4,
            expected: Math.log(4),
          }
        ];
        for (const { parameter, expected, MessageErr } of testcase){
            if (expected == Error) {
            assert.throws(() => calculator.log(parameter), Error(MessageErr));
          } else {
            assert.strictEqual(calculator.log(parameter), expected);
          }
        };
      });
    });