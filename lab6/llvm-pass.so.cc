#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();
    IntegerType *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = Type::getInt8PtrTy(Ctx);

    // 建立 debug 函數原型：void debug(int)
    FunctionType *DebugTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
    FunctionCallee DebugFunc = M.getOrInsertFunction("debug", DebugTy);
    ConstantInt *Const48763 = ConstantInt::get(Int32Ty, 48763);

    // 建立 "hayaku... motohayaku!" 字串常數
    Constant *StrConstant = ConstantDataArray::getString(Ctx, "hayaku... motohayaku!", true);
    GlobalVariable *StrGlobal = new GlobalVariable(
        M, StrConstant->getType(), true,
        GlobalValue::PrivateLinkage, StrConstant, "lab6.msg");
    Value *StrPtr = ConstantExpr::getBitCast(StrGlobal, CharPtrTy);

    // 找到 main 函數
    Function *MainFunc = M.getFunction("main");
    if (!MainFunc) return PreservedAnalyses::all();

    // 取得 argc 和 argv
    auto ArgIter = MainFunc->arg_begin();
    Argument *Argc = &*ArgIter++;
    Argument *Argv = &*ArgIter;

    // 插入點：main 的開頭
    BasicBlock &EntryBB = MainFunc->getEntryBlock();
    IRBuilder<> Builder(&*EntryBB.getFirstInsertionPt());

    // 1. 呼叫 debug(48763)
    Builder.CreateCall(DebugFunc, {Const48763});

    // 2. argv[1] = "hayaku... motohayaku!"
    Value *Index1 = ConstantInt::get(Int32Ty, 1);
    Value *Argv1Ptr = Builder.CreateInBoundsGEP(
        Argv->getType()->getPointerElementType(), Argv, Index1);
    Builder.CreateStore(StrPtr, Argv1Ptr);

    // 3. 替換所有使用 argc 的地方為常數 48763（避免 illegal store）
    for (auto &BB : *MainFunc) {
      for (auto &Inst : BB) {
        for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
          if (Inst.getOperand(i) == Argc) {
            Inst.setOperand(i, Const48763);
          }
        }
      }
    }

    return PreservedAnalyses::none();
  }
};

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(LLVMPass());
                });
          }};
}
