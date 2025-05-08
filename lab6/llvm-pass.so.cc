#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
  PointerType *Int8PtrTy = Type::getInt8PtrTy(Ctx);

  FunctionType *DebugTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debug_func = M.getOrInsertFunction("debug", DebugTy);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  Constant *StrConstant = ConstantDataArray::getString(Ctx, "hayaku... motohayaku!", true);
  GlobalVariable *StrVar = new GlobalVariable(M, StrConstant->getType(), true,
                                               GlobalValue::PrivateLinkage, StrConstant, ".str.hayaku");
  Constant *Zero = ConstantInt::get(Int32Ty, 0);
  Constant *Indices[] = {Zero, Zero};
  Constant *StrPtr = ConstantExpr::getGetElementPtr(StrConstant->getType(), StrVar, Indices);

  for (auto &F : M) {
    if (F.getName() != "main")
      continue;

    errs() << "Instrumenting function: " << F.getName() << "\n";
    IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

    Builder.CreateCall(debug_func, {debug_arg});

    auto ArgIter = F.arg_begin();
    Argument *argcArg = ArgIter++;
    Argument *argvArg = ArgIter;

    Value *Argv1Ptr = Builder.CreateGEP(Int8PtrTy, argvArg, ConstantInt::get(Int32Ty, 1));
    Builder.CreateStore(StrPtr, Argv1Ptr);

    argcArg->replaceAllUsesWith(debug_arg);
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
