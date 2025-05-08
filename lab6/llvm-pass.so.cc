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
    if(F.getName() == "main") {
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

      // call debug
      Builder.CreateCall(debug_func, debug_arg);

      Argument *argc = F.getArg(0);
      argc->replaceAllUsesWith(debug_arg);

      Argument *argv = F.getArg(1);
      Value *argv_ptr = Builder.CreateGEP(Builder.getInt8PtrTy(), argv, ConstantInt::get(Int32Ty, 1));
      Value *newStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");

      Builder.CreateStore(newStr, argv_ptr);
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

