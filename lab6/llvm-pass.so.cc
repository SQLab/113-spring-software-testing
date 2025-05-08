#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);

  // Get or insert the debug function with correct type
  FunctionType *debugTy =
      FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debug_func = M.getOrInsertFunction("debug", debugTy);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    if (F.getName() == "main") {
      // Get the first insertion point in the entry block
      BasicBlock::iterator IP = F.getEntryBlock().getFirstInsertionPt();
      IRBuilder<> Builder(&(*IP));

      // Call debug function with 48763
      Builder.CreateCall(debug_func, {debug_arg});

      // Get argc and argv arguments
      Argument *argc = F.getArg(0);
      Argument *argv = F.getArg(1);

      // Replace all uses of argc with 48763
      argc->replaceAllUsesWith(debug_arg);

      // Create argv[1] pointer and store our string
      Value *argv1_ptr = Builder.CreateGEP(Builder.getInt8PtrTy(), argv,
                                           ConstantInt::get(Int32Ty, 1));
      Value *new_str = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(new_str, argv1_ptr);
    }
  }
  return PreservedAnalyses::none();
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0", [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(LLVMPass());
                });
          }};
}
