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
  // Prepare debug function and argument
  FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    if (F.getName() == "main") {
      // 1. Invoke debug function with the first argument is 48763 in main function.
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
      Builder.CreateCall(debug_func, {debug_arg});
      
      // 2. Modify argv[1] to a custom string
      Argument *argv_arg = F.getArg(1);
      Value *index = ConstantInt::get(Int32Ty, 1);
      Value *argv_ptr = Builder.CreateInBoundsGEP(Builder.getInt8PtrTy(), argv_arg, index);
      Value *custom_str = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(custom_str, argv_ptr);
      
      // 3.  Replace all uses of argc with the debug ID = 48763
      Argument *argc_arg = F.getArg(0);
      argc_arg->replaceAllUsesWith(debug_arg);
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

