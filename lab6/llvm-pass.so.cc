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
    if(F.getName()=="main"){
      BasicBlock &entryBlock = F.getEntryBlock();
      IRBuilder<> builder(&*entryBlock.getFirstInsertionPt());

      builder.CreateCall(debug_func, debug_arg);

      // 把所有用到 argc 的地方 全部替換成48763
      ConstantInt *main_argc = ConstantInt::get(Int32Ty, 48763);
      Argument *argcArg = F.getArg(0);
      argcArg->replaceAllUsesWith(main_argc);

      
      Argument *argvArg = F.getArg(1);
      Value *str = builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Type *argvElementType = argvArg->getType()->getPointerElementType();
      ConstantInt *offset = ConstantInt::get(Int32Ty, 1);
      Value *ptrToArgv1 = builder.CreateInBoundsGEP(argvElementType, argvArg, offset);
      builder.CreateStore(str, ptrToArgv1);
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

