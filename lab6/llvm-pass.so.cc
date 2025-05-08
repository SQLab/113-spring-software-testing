#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();
    IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *i8PtrTy = Type::getInt8PtrTy(Ctx);

    // debug(int)
    FunctionCallee debugFunc = M.getOrInsertFunction("debug", FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false));
    ConstantInt *debugArg = ConstantInt::get(Int32Ty, 48763);

    Function *mainFunc = M.getFunction("main");
    if (!mainFunc) return PreservedAnalyses::none();

    IRBuilder<> Builder(&*mainFunc->getEntryBlock().getFirstInsertionPt());

    // call debug(48763)
    Builder.CreateCall(debugFunc, {debugArg});

    // replace argc (arg0) to 48763
    Argument *argcArg = nullptr, *argvArg = nullptr;
    auto it = mainFunc->arg_begin();
    argcArg = it++;
    argvArg = it;

    // alloc argc, store 48763
    AllocaInst *argcAlloca = Builder.CreateAlloca(Int32Ty, nullptr, "argcVar");
    Builder.CreateStore(debugArg, argcAlloca);

    // replace all uses of argcArg (except alloca) with loaded version
    argcArg->replaceAllUsesWith(Builder.CreateLoad(Int32Ty, argcAlloca));

    // insert global string "hayaku... motohayaku!"
    std::string msg = "hayaku... motohayaku!";
    Constant *strConstant = ConstantDataArray::getString(Ctx, msg, true);
    GlobalVariable *strVar = new GlobalVariable(
        M, strConstant->getType(), true,
        GlobalValue::PrivateLinkage, strConstant, "msg");

    // get i8* to string
    Value *strPtr = Builder.CreateGEP(
        strConstant->getType(),
        strVar,
        {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 0)}
    );

    // argv[1] = strPtr
    Value *argv1Ptr = Builder.CreateGEP(
        i8PtrTy, argvArg,
        ConstantInt::get(Int32Ty, 1)
    );
    Builder.CreateStore(strPtr, argv1Ptr);

    return PreservedAnalyses::none();
  }
};

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(LLVMPass());
                });
          }};
}
