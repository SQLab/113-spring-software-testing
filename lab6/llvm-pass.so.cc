#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
  PointerType *CharPtrTy = Type::getInt8PtrTy(Ctx);
  PointerType *CharPtrPtrTy = PointerType::getUnqual(CharPtrTy);

  // Get reference to debug(int) function
  FunctionCallee debug_func = M.getOrInsertFunction("debug", Type::getVoidTy(Ctx), Int32Ty);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    errs() << "func: " << F.getName() << "\n";
    if (F.getName() == "main") {
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

      // Call debug(48763);
      Builder.CreateCall(debug_func, {debug_arg});

      // argc = 48763
      Argument *argcArg = F.getArg(0);
      argcArg->replaceAllUsesWith(debug_arg);

      // argv[1] = "hayaku... motohayaku!"
      Argument *argvArg = F.getArg(1);
      Value *index1 = ConstantInt::get(Int32Ty, 1);
      Value *argv1_ptr = Builder.CreateInBoundsGEP(CharPtrTy, argvArg, index1);
      Value *hayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(hayakuStr, argv1_ptr);
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
