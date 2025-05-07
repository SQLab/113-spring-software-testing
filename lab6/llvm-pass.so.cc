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

  // Get or insert debug function declaration
  FunctionType *debugTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debugFunc = M.getOrInsertFunction("debug", debugTy);
  ConstantInt *debugArg = ConstantInt::get(Int32Ty, 48763);

  for (auto &F : M) {
    if (F.getName() != "main" || F.isDeclaration())
      continue;

    errs() << "instrumenting main\n";

    IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

    // Call debug(48763)
    Builder.CreateCall(debugFunc, {debugArg});

    // Get arguments
    auto ArgIter = F.arg_begin();
    Argument *argcArg = &*ArgIter++;
    Argument *argvArg = &*ArgIter;

    // Allocate space and store 48763 to replace argc
    AllocaInst *argcAlloca = Builder.CreateAlloca(Int32Ty, nullptr, "argcVar");
    Builder.CreateStore(debugArg, argcAlloca);

    // Replace uses of argcArg with loaded value
    for (auto &BB : F) {
      for (auto &I : BB) {
        for (unsigned i = 0; i < I.getNumOperands(); ++i) {
          if (I.getOperand(i) == argcArg) {
            // Load from new variable instead of using original argc
            IRBuilder<> B(&I);
            Value *loadedArgc = B.CreateLoad(Int32Ty, argcAlloca);
            I.setOperand(i, loadedArgc);
          }
        }
      }
    }

    // Replace argv[1] = "hayaku... motohayaku!"
    Value *index1 = ConstantInt::get(Int32Ty, 1);
    Value *argv1Ptr = Builder.CreateInBoundsGEP(argvArg->getType()->getPointerElementType(), argvArg, index1);
    Value *hayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
    Builder.CreateStore(hayakuStr, argv1Ptr);
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
