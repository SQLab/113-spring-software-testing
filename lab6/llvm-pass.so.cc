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
  FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);



  for (auto &F : M) {



 // Find main function, call the debug function with argument 48763

    if (F.getName() == "main"){
    IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
    Builder.CreateCall(debug_func, {debug_arg});

 // Overwrote argv1 with string "hayaku... motohayaku!"
    Argument *argvArg = F.getArg(1);
    Value *index1 = ConstantInt::get(Int32Ty, 1);
    Value *argv1_ptr = Builder.CreateInBoundsGEP(CharPtrTy, argvArg, index1);
    Value *hayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
    Builder.CreateStore(hayakuStr, argv1_ptr);

 // Overwrote argcArg with 48763
    Argument *argcArg = F.getArg(0);
    argcArg -> replaceAllUsesWith(debug_arg);

    }




  }
  return PreservedAnalyses::none();
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
    [](PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel OL) {
          MPM.addPass(LLVMPass());
        });
    }};
}

