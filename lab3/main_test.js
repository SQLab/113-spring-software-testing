const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
it('Param-Error', () => {
    const exp_testcases = [
        {param: NaN, expected: {name: 'Error', message: 'unsupported operand type'}},
        {param: 9999999, expected: {name: 'Error', message: 'overflow'}}
    ];

    const Calc = new Calculator();

    for( const ts of exp_testcases){
        assert.throws(() => {
            Calc.exp(ts.param);
        }, ts.expected
        );
    };

    const log_testcases = [
        {param: NaN, expected: {name: 'Error', message: 'unsupported operand type'}},
        {param: 0, expected: {name: 'Error', message: 'math domain error (1)'}},
        {param: -1, expected: {name: 'Error', message: 'math domain error (2)'}}
    ];

    for( const ts of log_testcases){
        assert.throws(() => {
            Calc.log(ts.param);
        }, ts.expected
        );
    };

})

it('test', () => {
    const exp_testcases = [
        {param: 0, expected: 1},
        {param: 1, expected: Math.exp(1)},
        {param: -1, expected: Math.exp(-1)}
    ];

    const Calc = new Calculator();

    for( const ts of exp_testcases){
        assert.strictEqual(Calc.exp(ts.param), ts.expected);
    };

    const log_testcases = [
        {param: 9, expected: Math.log(9)},
        {param: 1, expected: Math.log(1)},
        {param: 100, expected: Math.log(100)}
    ];

    for( const ts of log_testcases){
        assert.strictEqual(Calc.log(ts.param), ts.expected);
    };

})