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
    
    if(F.getName() == "main") {
      LLVMContext &Ctx = F.getContext();
        IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

        // Set argc = 48763
        Argument *argcArg = F.getArg(0);
        Value *argcConst = ConstantInt::get(argcArg->getType(), 48763);
        argcArg->replaceAllUsesWith(argcConst);

        // argv[1] = "hayaku... motohayaku!"
        Argument *argvArg = F.getArg(1);
        PointerType *CharPtrTy = Type::getInt8PtrTy(Ctx);
        Value *Index1 = ConstantInt::get(Type::getInt32Ty(Ctx), 1);
        Value *PtrToArgv1 = Builder.CreateGEP(CharPtrTy, argvArg, Index1);
        Value *HayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
        Builder.CreateStore(HayakuStr, PtrToArgv1);

        // Insert call to debug(48763)
        Module *M = F.getParent();
        FunctionCallee DebugFunc = M->getOrInsertFunction("debug", FunctionType::get(Type::getVoidTy(Ctx), { Type::getInt32Ty(Ctx) }, false));
        Builder.CreateCall(DebugFunc, { ConstantInt::get(Type::getInt32Ty(Ctx), 48763) });
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

