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
    if (F.getName() == "main") {
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

      // 1. 插入 debug(48763);
      Builder.CreateCall(debug_func, debug_arg);

      // 2. 將 argv[1] = "hayaku... motohayaku!"
      // 建立常數字串
      Constant *StrConstant = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "hayaku_str");

      // 取得參數 argc 和 argv
      Function::arg_iterator args = F.arg_begin();
      Value *argcArg = &*args++;
      Value *argvArg = &*args;

      // 正確計算 argv[1] 的位址並存入字串
      Value *argv1Ptr = Builder.CreateInBoundsGEP(
          PointerType::getUnqual(Type::getInt8PtrTy(Ctx)),
          argvArg,
          {ConstantInt::get(Int32Ty, 1)},
          "argv1_ptr"
      );
      Builder.CreateStore(StrConstant, argv1Ptr);

      // 3. 將所有 argc 的用法替換為常數 48763
      for (auto it = argcArg->use_begin(), et = argcArg->use_end(); it != et;) {
        Use &use = *it++;
        use.set(debug_arg);
      }
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

