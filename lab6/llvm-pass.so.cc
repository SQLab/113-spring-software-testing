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

  bool Modified = false;

  for (auto &F : M) {
    errs() << "func: " << F.getName() << "\n";

    if (F.getName() != "main") continue;
    BasicBlock &EntryBB = F.getEntryBlock();
    IRBuilder<> Builder(&*EntryBB.getFirstInsertionPt());
    // 1：Insert debug(48763)
    Builder.CreateCall(debug_func, {debug_arg});

    // 2：Set argv[1] to "hayaku... motohayaku!"
    Constant *StrConst = ConstantDataArray::getString(Ctx, "hayaku... motohayaku!");
    GlobalVariable *StrVar = new GlobalVariable(
        M, StrConst->getType(), true, GlobalValue::PrivateLinkage, StrConst, ".str");
    Constant *StrPtr = ConstantExpr::getPointerCast(StrVar, Type::getInt8PtrTy(Ctx));

    // Get argv[1]
    Value *Argv = F.getArg(1);
    // Calculate the address of argv[1]（argv + 1）
    Value *Argv1Ptr = Builder.CreateGEP(Type::getInt8PtrTy(Ctx), Argv,
                                       ConstantInt::get(Type::getInt64Ty(Ctx), 1));
    // Set argv[1] to new string
    Builder.CreateStore(StrPtr, Argv1Ptr);

    // 3：Set argc to 48763
    Value *Argc = F.getArg(0);
    Value *ArgcPtr = Builder.CreateAlloca(Int32Ty, nullptr, "argc.ptr");
    Builder.CreateStore(debug_arg, ArgcPtr);
    Argc->replaceAllUsesWith(Builder.CreateLoad(Int32Ty, ArgcPtr));
    Modified = true;
  }
  return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
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

