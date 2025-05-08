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
  PointerType *charPtrTy = Type::getInt8PtrTy(Ctx);

  // Find main()
  Function *mainFunc = nullptr;
  for (Function &F : M) {
    if (F.getName() == "main") {
      mainFunc = &F;
      break;
    }
  }
  if (!mainFunc) return PreservedAnalyses::none();

  IRBuilder<> builder(&*mainFunc->getEntryBlock().getFirstInsertionPt());

  FunctionType *debugType = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debugFunc = M.getOrInsertFunction("debug", debugType);
  Value *debugArg = ConstantInt::get(Int32Ty, 48763);
  builder.CreateCall(debugFunc, {debugArg});

  Argument *argcArg = mainFunc->getArg(0); // int argc
  AllocaInst *argcAlloca = builder.CreateAlloca(Int32Ty, nullptr, "argc.alloca");
  builder.CreateStore(ConstantInt::get(Int32Ty, 48763), argcAlloca);

  for (auto &BB : *mainFunc) {
    for (auto &I : BB) {
      for (unsigned i = 0; i < I.getNumOperands(); ++i) {
        if (I.getOperand(i) == argcArg) {
          IRBuilder<> tmpBuilder(&I);
          LoadInst *argcVal = tmpBuilder.CreateLoad(Int32Ty, argcAlloca);
          I.setOperand(i, argcVal);
        }
      }
    }
  }

  Argument *argvArg = mainFunc->getArg(1); // char **argv
  Value *strPtr = builder.CreateGlobalStringPtr("hayaku... motohayaku!", "str");
  Value *argv1Ptr = builder.CreateGEP(charPtrTy, argvArg, ConstantInt::get(Int32Ty, 1));
  builder.CreateStore(strPtr, argv1Ptr);

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
