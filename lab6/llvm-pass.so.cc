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
    errs() << "func: " << F.getName() << "\n";
    if (F.getName() == "main") {
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

      Builder.CreateCall(debug_func, debug_arg);

      Argument *ArgcArg = F.getArg(0);
      ArgcArg->replaceAllUsesWith(debug_arg); 

      Argument *ArgvArg = F.getArg(1); 
      Value *GEP = Builder.CreateInBoundsGEP(
          Int8PtrTy,
          ArgvArg,
          ConstantInt::get(Int32Ty, 1)
      );
      Value *StrVal = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(StrVal, GEP);
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

