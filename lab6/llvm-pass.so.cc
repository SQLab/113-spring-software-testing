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
    // if(F.getName() == "debug") {
    //   errs() << "debug find!\n";
    //   for(auto it = F.arg_begin(); it != F.arg_end(); it++) {
    //     errs() << *it << "\n";
    //   }
    // }

    if(F.getName() == "main") {
      BasicBlock::iterator IP = F.begin()->getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      IRB.CreateCall(debug_func, debug_arg);
      
      Argument *argc = F.getArg(0);
      argc->replaceAllUsesWith(debug_arg);

      Argument *argv = F.getArg(1);
      Value *Argv1_Ptr = IRB.CreateGEP(IRB.getInt8PtrTy(), argv, ConstantInt::get(Int32Ty, 1));
      Value *Argv1_Value = IRB.CreateGlobalStringPtr("hayaku... motohayaku!");
      IRB.CreateStore(Argv1_Value, Argv1_Ptr);

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

