PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {


   LLVMContext &Ctx = M.getContext();
   IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
   FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
   FunctionCallee debug_func = M.getOrInsertFunction("debug", FTy);
   ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);
   for (auto &F : M) 
   {
     //errs() << "func: " << F.getName() << "\n";
 	  if (F.getName()=="main"){
       BasicBlock& BB =F.getEntryBlock();
       //errs() << "BB: " <<BB;
       auto IP = BB.getFirstInsertionPt();
       IRBuilder<> IRB(&*IP);
       IRB.CreateCall(debug_func, debug_arg);
       Argument &Arg = *F.arg_begin();
       Arg.replaceAllUsesWith(debug_arg);
       Function::arg_iterator args = F.arg_begin();
       ++args;
       Value *Ar = IRB.CreateGlobalStringPtr("hayaku... motohayaku!");
       Argument *argv = args;
       Value *idx1 = ConstantInt::get(Type::getInt32Ty(Ctx), 1);
       Value *argv1_ptr = IRB.CreateInBoundsGEP(argv->getType()->getPointerElementType(), argv, idx1, "argv1ptr");
       IRB.CreateStore(Ar, argv1_ptr);
 		}

   }
   return PreservedAnalyses::none();
 }