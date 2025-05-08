#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

bool registerCustomPipeline(StringRef, ModulePassManager&, ArrayRef<PassBuilder::PipelineElement>);
void injectAtStart(ModulePassManager&, OptimizationLevel);

namespace {
struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &Mod, ModuleAnalysisManager &) {
    Function *MainFunc = Mod.getFunction("main");
    if (!MainFunc) return PreservedAnalyses::all();

    LLVMContext &Context = Mod.getContext();
    IRBuilder<> Builder(&*MainFunc->getEntryBlock().getFirstInsertionPt());

    FunctionCallee DebugCall = Mod.getOrInsertFunction(
        "debug", FunctionType::get(Type::getVoidTy(Context), {Type::getInt32Ty(Context)}, false));
    Builder.CreateCall(DebugCall, ConstantInt::get(Type::getInt32Ty(Context), 48763));

    auto ArgIter = MainFunc->arg_begin();
    Argument *ArgCount = &*ArgIter++;
    Argument *ArgList = &*ArgIter;

    Value *FixedVal = ConstantInt::get(Type::getInt32Ty(Context), 48763);
    AllocaInst *FakeArgc = Builder.CreateAlloca(Type::getInt32Ty(Context), nullptr, "argc_temp");
    Builder.CreateStore(FixedVal, FakeArgc);

    for (auto UI = ArgCount->use_begin(), UE = ArgCount->use_end(); UI != UE;) {
      Use &U = *UI++;
      U.set(Builder.CreateLoad(Type::getInt32Ty(Context), FakeArgc));
    }

    Value *Str = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "msg_str");
    Value *Index = ConstantInt::get(Type::getInt32Ty(Context), 1);
    Value *ArgvSlot = Builder.CreateGEP(
        ArgList->getType()->getPointerElementType(), ArgList, Index);
    Builder.CreateStore(Str, ArgvSlot);

    return PreservedAnalyses::none();
  }
};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  static const PassPluginLibraryInfo Info{
    LLVM_PLUGIN_API_VERSION, "LLVMPass", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(registerCustomPipeline);
      PB.registerPipelineStartEPCallback(injectAtStart);
    }
  };
  return Info;
}

bool registerCustomPipeline(StringRef Name, ModulePassManager &PM, ArrayRef<PassBuilder::PipelineElement>) {
  if (Name == "llvm-pass") {
    PM.addPass(LLVMPass());
    return true;
  }
  return false;
}

void injectAtStart(ModulePassManager &PM, OptimizationLevel) {
  PM.addPass(LLVMPass());
}
