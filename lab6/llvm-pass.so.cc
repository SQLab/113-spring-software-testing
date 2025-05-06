#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IRBuilder<> Builder(Ctx);

  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
  PointerType *I8PtrTy  = Type::getInt8PtrTy(Ctx); // for argv

  FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);
  Constant *StrGlobal = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "",
    0, &M); // for argv

  for (auto &F : M) {
    if (F.getName() == "main"){
      // insert debug
      BasicBlock &Entry = F.getEntryBlock();
      Builder.SetInsertPoint(&*Entry.getFirstInsertionPt());
      Builder.CreateCall(debug_func, {debug_arg});

      // insert argc, argv
      auto ArgIter = F.arg_begin();
      Argument *Argc = &*ArgIter++;
      Argument *Argv = &*ArgIter; 
      // replace argc -> i8, hayaku... motohayaku!
      Value *Idx1    = Builder.getInt32(1);
      Value *Argv1Ptr= Builder.CreateGEP(I8PtrTy, Argv, Idx1);
      Builder.CreateStore(StrGlobal, Argv1Ptr);
      // replace argv -> debug_arg 48763
      if (!Argc->use_empty()) Argc->replaceAllUsesWith(debug_arg);
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

