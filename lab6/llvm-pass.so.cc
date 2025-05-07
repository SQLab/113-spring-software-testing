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
  IntegerType *Int64Ty = IntegerType::getInt64Ty(Ctx);
  FunctionCallee debug_func = M.getOrInsertFunction("debug", Int32Ty);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    if (!F.getName().equals("main"))
      continue;

    IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
    Builder.CreateCall(debug_func, debug_arg);

    Argument *Arg1 = F.getArg(1);
    Value *Idx1   = ConstantInt::get(Int64Ty, 1);
    Value *Arg1Ptr = Builder.CreateInBoundsGEP(Type::getInt8PtrTy(Ctx), Arg1, Idx1);

    Value *Kirito = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "hayaku");
    Builder.CreateStore(Kirito, Arg1Ptr);
    
    Argument *Arg0 = F.getArg(0);
    for (Instruction &I : instructions(F)) {
      if (auto *SI = dyn_cast<StoreInst>(&I)) {
        if (SI->getValueOperand() == Arg0) {
          IRBuilder<> B(SI->getNextNode());
          B.CreateStore(debug_arg, SI->getPointerOperand());
          break;
        }
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

