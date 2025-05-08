#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
  PointerType *CharPtrTy = Type::getInt8PtrTy(Ctx);
  
  // Get or create debug function declaration
  FunctionCallee debug_func = M.getOrInsertFunction("debug", 
    FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false));
  
  // Create constant value for debug function argument and argc
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);
  
  for (auto &F : M) {
    // Find main function
    if (F.getName() == "main") {
      // Create IRBuilder at the beginning of the entry block
      IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
      
      // a. Call debug function with argument 48763
      Builder.CreateCall(debug_func, {debug_arg});
      
      // Get function arguments
      Argument *argcArg = F.getArg(0);
      Argument *argvArg = F.getArg(1);
      
      // b. Set argv[1] = "hayaku... motohayaku!"
      Value *index1 = ConstantInt::get(Int32Ty, 1);
      Value *argv1_ptr = Builder.CreateInBoundsGEP(CharPtrTy, argvArg, index1);
      Value *hayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
      Builder.CreateStore(hayakuStr, argv1_ptr);
      
      // c. Replace all uses of argc with 48763
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