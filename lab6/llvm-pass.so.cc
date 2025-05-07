#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &ctx = M.getContext();

    // Find the main function
    Function *main_fn = M.getFunction("main");
    assert(main_fn && main_fn->arg_size() >= 2);

    // Find the debug function
    auto debug_fn = M.getFunction("debug");
    assert(debug_fn);

    // Insert the debug function call at the beginning of main
    IRBuilder<> main_ir_builder(&main_fn->getEntryBlock().front());
    // call the debug function with 48763
    main_ir_builder.CreateCall(debug_fn, {ConstantInt::get(Type::getInt32Ty(ctx), 48763)});

    // Find argc and argv
    auto args_iter = main_fn->arg_begin();
    Argument &argc = *args_iter++;
    Argument &argv = *args_iter++;

    // Replace argc to 48763
    auto new_argc = ConstantInt::get(argc.getType(), 48763);
    argc.replaceAllUsesWith(new_argc);

    // create the target string
    auto target_value = ConstantDataArray::getString(ctx, "hayaku... motohayaku!", true);
    auto target = cast<GlobalVariable>(M.getOrInsertGlobal("target", target_value->getType()));
    target->setInitializer(target_value);
    target->setLinkage(GlobalValue::InternalLinkage);

    // create a {..., target} array
    auto new_argv_value = ConstantArray::get(ArrayType::get(target->getType(), 2),
                                             ArrayRef<Constant *>{target, target});
    auto new_argv = cast<GlobalVariable>(M.getOrInsertGlobal("my_argv", new_argv_value->getType()));
    new_argv->setInitializer(new_argv_value);
    new_argv->setLinkage(GlobalValue::InternalLinkage);

    // Replace argv to target_array
    argv.replaceAllUsesWith(new_argv);

    return PreservedAnalyses::none();
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0", [](PassBuilder &PB) {
                PB.registerOptimizerLastEPCallback(
                    [](ModulePassManager &MPM, OptimizationLevel OL) { MPM.addPass(LLVMPass()); });
            }};
}
