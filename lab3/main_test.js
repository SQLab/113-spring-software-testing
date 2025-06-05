const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

describe('Calculator', () => {
  describe('exp(x)', () => {
   
    const validInputs = [
      { x: 0, expected: 1 },
      { x: 1, expected: Math.E },
      { x: 2, expected: Math.E * Math.E },
      { x: -1, expected: 1 / Math.E },
      { x: 0.5, expected: Math.sqrt(Math.E) }
    ];

    for (const { x, expected } of validInputs) {
      it(`should correctly calculate exp(${x})`, () => {
        const calculator = new Calculator();
        const result = calculator.exp(x);
        
        const epsilon = 1e-10;
        assert.ok(Math.abs(result - expected) < epsilon, 
          `Expected ${result} to be approximately equal to ${expected}`);
      });
    }

    
    const invalidInputTypes = [
      { x: NaN, errorMsg: 'unsupported operand type' },
      { x: Infinity, errorMsg: 'unsupported operand type' },
      { x: -Infinity, errorMsg: 'unsupported operand type' }
    ];

    for (const { x, errorMsg } of invalidInputTypes) {
      it(`should throw error for exp(${x})`, () => {
        const calculator = new Calculator();
        assert.throws(() => {
          calculator.exp(x);
        }, { message: errorMsg });
      });
    }

   
    it('should throw overflow error for very large input', () => {
      const calculator = new Calculator();
      assert.throws(() => {
        calculator.exp(1000); 
      }, { message: 'overflow' });
    });
  });

  describe('log(x)', () => {
    
    const validInputs = [
      { x: 1, expected: 0 },
      { x: Math.E, expected: 1 },
      { x: Math.E * Math.E, expected: 2 },
      { x: 10, expected: Math.log(10) },
      { x: 0.5, expected: Math.log(0.5) }
    ];

    for (const { x, expected } of validInputs) {
      it(`should correctly calculate log(${x})`, () => {
        const calculator = new Calculator();
        const result = calculator.log(x);
        const epsilon = 1e-10;
        assert.ok(Math.abs(result - expected) < epsilon, 
          `Expected ${result} to be approximately equal to ${expected}`);
      });
    }

    const invalidInputTypes = [
      { x: NaN, errorMsg: 'unsupported operand type' },
      { x: Infinity, errorMsg: 'unsupported operand type' },
      { x: -Infinity, errorMsg: 'unsupported operand type' }
    ];

    for (const { x, errorMsg } of invalidInputTypes) {
      it(`should throw error for log(${x})`, () => {
        const calculator = new Calculator();
        assert.throws(() => {
          calculator.log(x);
        }, { message: errorMsg });
      });
    }

    
    it('should throw math domain error (1) for log(0)', () => {
      const calculator = new Calculator();
      assert.throws(() => {
        calculator.log(0);
      }, { message: 'math domain error (1)' });
    });

  
    const negativeInputs = [
      -1, -0.5, -10, -100
    ];

    for (const x of negativeInputs) {
      it(`should throw math domain error (2) for log(${x})`, () => {
        const calculator = new Calculator();
        assert.throws(() => {
          calculator.log(x);
        }, { message: 'math domain error (2)' });
      });
    }
  });
});