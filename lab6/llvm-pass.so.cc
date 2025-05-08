#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();
    IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *Int8PtrTy = Type::getInt8PtrTy(Ctx);

    // Declare: void debug(int)
    FunctionCallee debugFunc = M.getOrInsertFunction("debug", FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false));
    ConstantInt *debugID = ConstantInt::get(Int32Ty, 48763);

    for (auto &F : M) {
      if (F.getName() == "main") {
        IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

        // Inject debug(48763);
        Builder.CreateCall(debugFunc, {debugID});

        // Get main args
        auto args = F.args().begin();
        Argument *argcArg = args++;
        Argument *argvArg = args;

        // === Overwrite argc to 48763 ===
        // Allocate space and overwrite
        AllocaInst *argcAlloca = Builder.CreateAlloca(Int32Ty, nullptr, "argc.fake");
        Builder.CreateStore(ConstantInt::get(Int32Ty, 48763), argcAlloca);

        // Replace all uses of argcArg with loaded value
        for (auto &BB : F) {
          for (auto &I : BB) {
            for (unsigned i = 0; i < I.getNumOperands(); ++i) {
              if (I.getOperand(i) == argcArg) {
                IRBuilder<> tmpBuilder(&I);
                LoadInst *argcLoad = tmpBuilder.CreateLoad(Int32Ty, argcAlloca);
                I.setOperand(i, argcLoad);
              }
            }
          }
        }

        // === Overwrite argv[1] ===
        Value *index1 = ConstantInt::get(Int32Ty, 1);
        Value *argv1Ptr = Builder.CreateGEP(argvArg->getType()->getPointerElementType(), argvArg, index1);
        Value *newStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!");
        Builder.CreateStore(newStr, argv1Ptr);
      }
    }

    return PreservedAnalyses::none();
  }
};

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(LLVMPass());
                });
          }};
}
