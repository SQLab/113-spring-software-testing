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
    //errs() << "func: " << F.getName() << "\n";
    if(F.getName() == "main")
    {
      //1. get into debug mode with id = 48763
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
      Builder.CreateCall(debug_func, {debug_arg});
      
      //2. let argv[1] to custom string
      Argument *argvArg = F.getArg(1);
      Value *index = ConstantInt::get(Int32Ty, 1);
      Value *argv_ptr = Builder.CreateInBoundsGEP(Builder.getInt8PtrTy(), argvArg, index); //指標指向的型別 (i8*)
      Value *custom = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(custom, argv_ptr); //將argv[1]位址指向custom並儲存

      //3. change argc to 48763
      Argument *argcArg = F.getArg(0);
      argcArg->replaceAllUsesWith(debug_arg);
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

