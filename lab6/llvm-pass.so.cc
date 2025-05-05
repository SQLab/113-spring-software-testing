#include "llvm/IR/IRBuilder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);

  FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
  Function *main_func = M.getFunction("main");
  IRBuilder<> Builder(&*main_func->getEntryBlock().getFirstInsertionPt());

  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);
  Builder.CreateCall(debug_func, {debug_arg});

  if (main_func->arg_size() >= 1) {
    Argument *argc = main_func->getArg(0);
    argc->replaceAllUsesWith(debug_arg);
  }

  if (main_func->arg_size() >= 2) {
    Argument *argv = main_func->getArg(1);
    Value *str_const = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
    Value *argv1_ptr = Builder.CreateGEP(
        argv->getType()->getPointerElementType(), argv, Builder.getInt32(1));
    Builder.CreateStore(str_const, argv1_ptr);
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
