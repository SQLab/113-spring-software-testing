#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// === 自定義註冊函式：提前宣告 ===
bool registerLLVMPipeline(StringRef, ModulePassManager&, ArrayRef<PassBuilder::PipelineElement>);
void autoStartLLVMPass(ModulePassManager&, OptimizationLevel);


namespace {
struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    // 嘗試取得 main 函式，若沒找到就不進行修改
    Function *Main = M.getFunction("main");
    if (!Main) return PreservedAnalyses::all();

    LLVMContext &Ctx = M.getContext();
    // 建立 IRBuilder，定位在 main 函式的進入點
    IRBuilder<> Builder(&Main->getEntryBlock().front());

    // === 呼叫 debug(48763) ===
    // 使用 getOrInsertFunction：如果已有 debug() 就使用它，否則插入。
    FunctionCallee DebugFunc = M.getOrInsertFunction("debug", FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx)}, false));
    // 建立一個  debug(48763) 的 IR 呼叫指令。
    Builder.CreateCall(DebugFunc, ConstantInt::get(Type::getInt32Ty(Ctx), 48763));

    // === 修改 argc, argv ===
    // main 函式的參數為 (int argc, char **argv)
    auto ArgIt = Main->arg_begin();
    Argument *Argc = &*ArgIt++;
    Argument *Argv = &*ArgIt;

    // 將 48763 寫入暫存變數
    auto *MagicNum = ConstantInt::get(Type::getInt32Ty(Ctx), 48763);
    auto *TempArgc = Builder.CreateAlloca(Type::getInt32Ty(Ctx), nullptr, "argc_tmp");
    Builder.CreateStore(MagicNum, TempArgc);

    // 然後替換 argc
    for (auto UI = Argc->use_begin(), UE = Argc->use_end(); UI != UE;) {
      Use &U = *UI++;
      U.set(Builder.CreateLoad(Type::getInt32Ty(Ctx), TempArgc));
    }

    // 修改 argv[1] = "hayaku... motohayaku!"
    // 建立一個 global 字串
    auto *HayakuStr = Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "hayaku_str");
    // 拿到 argv[1] 的記憶體位置
    auto *Argv1Ptr = Builder.CreateGEP(Argv->getType()->getPointerElementType(), Argv,
                                       ConstantInt::get(Type::getInt32Ty(Ctx), 1));
    Builder.CreateStore(HayakuStr, Argv1Ptr);

    return PreservedAnalyses::none();
  }
};
}

// 註冊 Pass
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  static const PassPluginLibraryInfo Info{
    LLVM_PLUGIN_API_VERSION, "LLVMPass", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(registerLLVMPipeline);
      PB.registerPipelineStartEPCallback(autoStartLLVMPass);
    }
  };
  return Info;
}

bool registerLLVMPipeline(StringRef Name, ModulePassManager &PM, ArrayRef<PassBuilder::PipelineElement>) {
  if (Name == "llvm-pass") {
    PM.addPass(LLVMPass());
    return true;
  }
  return false;
}

void autoStartLLVMPass(ModulePassManager &PM, OptimizationLevel) {
  PM.addPass(LLVMPass());
}

