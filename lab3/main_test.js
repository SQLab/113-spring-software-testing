const {describe, it} = require('node:test');
const assert = require('assert');
const { Calculator } = require('./main');

// TODO: write your tests here
// chatGPT gives examples of describe and it function
describe(('test Parameterization'),(t)=>{
    const cal = new Calculator();
    const testcaseexp = [{
        para:0,expected:1,
        para:1,expected:2.718281828459045,
    }]
    const testcaselog = [{
        para:1,expected:0
    }]
    it (('test exp logic'),()=>{
        for (const tc of testcaseexp){
            assert.strictEqual(cal.exp(tc.para),tc.expected);
        }
    })
    it (('test log logic'),()=>{
        for (const tc of testcaselog){
            assert.strictEqual(cal.log(tc.para),tc.expected);
        }
    })
    
});

describe(('test error'),(t)=>{

    const cal = new Calculator();
    it (('test exp error',()=>{
        assert.throws(()=>{
            cal.exp('a');
        },{
            name:'Error',
            message:'unsupported operand type'
        });
        assert.throws(()=>{
            cal.exp(555555555555555555555555555555555555555555555555);
        },{
            name:'Error',
            message:'overflow'
        });
    }));
    it(('test log error'),()=>{
        assert.throws(()=>{
            cal.log(0);
        },{
            name:'Error',
            message:'math domain error (1)'
        });
        assert.throws(()=>{
            cal.log('a');
        },{
            name:'Error',
            message:'unsupported operand type'
        });
        assert.throws(()=>{
            cal.log(-1);
        },{
            name:'Error',
            message:'math domain error (2)'
        });
    });
});
