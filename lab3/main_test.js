const { describe, it } = require('node:test')
const assert = require('assert')
const { Calculator } = require('./main')

describe('Test Calculator.exp', () => {
  const calculator = new Calculator()

  it('Integers should return result successfully', () => {
    const testcases = [
      { x: 1, expected: Math.exp(1) },
      { x: 10, expected: Math.exp(10) },
      { x: -1, expected: Math.exp(-1) },
      { x: -20, expected: Math.exp(-20) },
    ]

    for (const testcase of testcases) {
      assert.strictEqual(calculator.exp(testcase.x), testcase.expected)
    }
  })

  it('Infinite numbers should raise unsupported operand type error', () => {
    const testcases = [NaN, Infinity, -Infinity]

    for (const testcase of testcases) {
      assert.throws(() => calculator.exp(testcase), /^Error: unsupported operand type$/)
    }
  })

  it('Infinite result should raise overflow error', () => {
    assert.throws(() => calculator.exp(2e64), /^Error: overflow$/)
  })
})

describe('Test Calculator.log', () => {
  const calculator = new Calculator()

  it('Nature numbers should return result successfully', () => {
    const testcases = [
      { x: 10, expected: Math.log(10) },
      { x: 99, expected: Math.log(99) },
    ]

    for (const testcase of testcases) {
      assert.strictEqual(calculator.log(testcase.x), testcase.expected)
    }
  })

  it('Infinite numbers should raise unsupported operand type error', () => {
    const testcases = [NaN, Infinity, -Infinity]

    for (const testcase of testcases) {
      assert.throws(() => calculator.log(testcase), /^Error: unsupported operand type$/)
    }
  })

  it('Zero should raise math domain error (1)', () => {
    assert.throws(() => calculator.log(0), /^Error: math domain error \(1\)$/)
  })

  it('Negative numbers should raise math domain error (2)', () => {
    const testcases = [-1, -10, -99]

    for (const testcase of testcases) {
      assert.throws(() => calculator.log(testcase), /^Error: math domain error \(2\)$/)
    }
  })
})
