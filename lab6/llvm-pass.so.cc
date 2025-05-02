#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
using namespace llvm;

namespace {

struct Lab6FinalPass : PassInfoMixin<Lab6FinalPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    auto *i32 = Type::getInt32Ty(C);
    auto *i8ptr = Type::getInt8PtrTy(C);

    // 宣告 debug 函數與 48763 常數
    auto debugTy = FunctionType::get(Type::getVoidTy(C), {i32}, false);
    auto debugFn = M.getOrInsertFunction("debug", debugTy);
    auto const48763 = ConstantInt::get(i32, 48763);

    // 建立常數字串 "hayaku... motohayaku!"
    auto strConst = ConstantDataArray::getString(C, "hayaku... motohayaku!", true);
    auto *gstr = new GlobalVariable(M, strConst->getType(), true,
                                    GlobalValue::PrivateLinkage, strConst, "haya_str");
    auto strPtr = ConstantExpr::getBitCast(gstr, i8ptr);

    // 找到 main 函式
    Function *main = M.getFunction("main");
    if (!main) return PreservedAnalyses::all();

    // IRBuilder 插入點設在 entry block 開頭
    IRBuilder<> B(&*main->getEntryBlock().getFirstInsertionPt());

    // 呼叫 debug(48763)
    B.CreateCall(debugFn, const48763);

    // 抓取 main 的參數
    Argument *argc = nullptr, *argv = nullptr;
    auto it = main->arg_begin();
    if (it != main->arg_end()) argc = it++;
    if (it != main->arg_end()) argv = it;

    // 覆寫 argv[1] 的記憶體：argv[1] = strPtr
    Value *idx[] = { ConstantInt::get(i32, 1) };
    Value *argv1Ptr = B.CreateInBoundsGEP(i8ptr, argv, idx);
    B.CreateStore(strPtr, argv1Ptr);

    // 遍歷整個函數，修改 argc 為常數，並處理 strcmp
    for (auto &BB : *main) {
      for (auto &I : BB) {
        // 修改使用 argc 的地方
        for (unsigned i = 0; i < I.getNumOperands(); ++i) {
          if (I.getOperand(i) == argc) {
            I.setOperand(i, const48763);
          }
        }

        // 如果遇到 strcmp(argv[1], ...) 則強制修改 argv[1] 為我們的字串
        if (auto *call = dyn_cast<CallInst>(&I)) {
          if (Function *callee = call->getCalledFunction()) {
            if (callee->getName() == "strcmp" && call->arg_size() >= 2) {
              call->setArgOperand(0, strPtr);
            }
          }
        }
      }
    }

    return PreservedAnalyses::none();
  }
};

} // namespace

// 註冊 Pass 到 New Pass Manager
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "Lab6FinalPass", "v1.0",
    [](PassBuilder &PB) {
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(Lab6FinalPass());
        });
    }
  };
}
