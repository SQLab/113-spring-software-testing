#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
using namespace llvm;
struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};
PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);

  FunctionType *debugTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debug_func = M.getOrInsertFunction("debug", debugTy);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    //errs() << "func: " << F.getName() << "\n";
    if(F.getName() != "main" || F.isDeclaration())
    	continue;

    errs() << "func: " << F.getName() << "\n";

    auto ArgIter = F.arg_begin();
    Argument *argcArg = &*ArgIter++;
    Argument *argvArg = &*ArgIter;

    Instruction *InsertPt = &*F.getEntryBlock().getFirstInsertionPt();
    IRBuilder<> Builder(InsertPt);

    Builder.CreateCall(debug_func, {debug_arg});

    for(auto &BB : F){
    	for(auto &I : BB){
    		for(unsigned i = 0; i < I.getNumOperands(); ++i){
    		if(I.getOperand(i) == argcArg){
    			I.setOperand(i, debug_arg);
    		}
    		}
    	}
    }

    Value *idx1 = ConstantInt::get(Int32Ty, 1);
    Value *argv1Ptr = Builder.CreateInBoundsGEP(argvArg->getType()->getPointerElementType(), argvArg, idx1);
    Value *strPtr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
    Builder.CreateStore(strPtr, argv1Ptr);

    //Builder.CreateStore(debug_arg, argcArg);

  }
  return PreservedAnalyses::none();