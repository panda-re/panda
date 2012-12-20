/*
 * This is the implementation of the things defined in laredo.h.
 */

#include "laredo.h"

extern "C" {
#include "guestarch.h"
extern int next_step;
extern int taken_branch;
extern DynValBuffer *dynval_buffer; // declared in taint.cpp
}

using namespace llvm;



/***
 *** LaredoTaintFunctionPass
 ***/



char LaredoTaintFunctionPass::ID = 0;
static RegisterPass<LaredoTaintFunctionPass>
X("laredo", "Analyze each instruction in a function for taint operations");

FunctionPass *llvm::createLaredoTaintFunctionPass(FILE *dlog,
    Shad *shad, TaintOpBuffer *tbuf, TaintTB *ttb, FILE *tc) {
    return new LaredoTaintFunctionPass(dlog, shad, tbuf, ttb, tc);
}

bool LaredoTaintFunctionPass::runOnFunction(Function &F){
    
#ifdef TAINTDEBUG
    printf("\n\n%s\n", F.getName().str().c_str());
#endif

    // check and see if cache needs to be flushed and if so, flush
    std::map<std::string, TaintTB*>::iterator it;
    if (ttbCache->size() == 10000){
        for (it = ttbCache->begin(); it != ttbCache->end(); it++){
            // don't remove helper functions from cache
            if (!strstr(it->second->name, "tcg-llvm-tb")){
                continue;
            }
            taint_tb_cleanup(it->second);
            ttbCache->erase(it);
        }
    }

    it = ttbCache->find(F.getName().str());
    if (it != ttbCache->end()){
#ifdef TAINTDEBUG
        printf("found\n");
#endif
        ttb = it->second;
    }

    else {

        ttb = taint_tb_new(F.getName().str().c_str(),
            (int)F.getBasicBlockList().size());

        // clear global taint op buffer
        tob_clear(tbuf);
        
        // process taint starting with the entry BB
        Function::iterator bb = F.begin();
        //printf("Processing entry BB...\n");
        LTV->visit(bb);

        ttb->entry->label = 0;
        ttb->entry->ops = tob_new(tbuf->size);
        tob_clear(ttb->entry->ops);
        memcpy(ttb->entry->ops->start, tbuf->start, tbuf->size);
        ttb->entry->ops->size = tbuf->size;

        // process other taint BBs if they exist
        int i = 0;
        if (ttb->numBBs > 1){
            bb++;
            for (Function::iterator bbe = F.end(); bb != bbe; bb++){

                // clear global taint op buffer
                tob_clear(tbuf);

                ttb->tbbs[i]->label = LTV->LST->getLocalSlot(bb);
                //printf("Processing BB %d...\n", LV->LST->getLocalSlot(bb));
                LTV->visit(bb);

                ttb->tbbs[i]->ops = tob_new(tbuf->size);
                tob_clear(ttb->tbbs[i]->ops);
                memcpy(ttb->tbbs[i]->ops->start, tbuf->start, tbuf->size);
                ttb->tbbs[i]->ops->size = tbuf->size;
                i++;
            }
        }

#ifndef TAINTSTATS
        // don't cache during statistics gathering because we need to keep
        // instruction count
        ttbCache->insert(std::pair<std::string, TaintTB*>(
            F.getName().str(), ttb));
#endif
    }

    // clean up until we implement caching
    //taint_tb_cleanup(ttb);
    //spit_mem_usage();

    return false; // no modifications made to function
}

void LaredoTaintFunctionPass::debugTaintOps(){
    int j = 0;
    tob_rewind(ttb->entry->ops);
    while (!(tob_end(ttb->entry->ops))) {
        TaintOp op = tob_op_read(ttb->entry->ops);
        printf("op %d ", j);
        tob_op_print(shad, op);
        j++;
    }

    // show taint ops for all BBs
    for (int i = 0; i < ttb->numBBs-1; i++){
        printf("\nBB %d:\n", ttb->tbbs[i]->label);
        
        j = 0;
        tob_rewind(ttb->tbbs[i]->ops);
        while (!(tob_end(ttb->tbbs[i]->ops))) {
            TaintOp op = tob_op_read(ttb->tbbs[i]->ops);
            printf("op %d ", j);
            tob_op_print(shad, op);
            j++;
        }
    }
}

/*
 * This probably isn't the safest code.  Please don't fuzz the cache file ;)
 */
void LaredoTaintFunctionPass::readTaintCache(){
    size_t cacheSize;
    char name[50];
    int numBBs;
    TaintTB *filettb;
    uint32_t taintbufsize;
    fread(&cacheSize, sizeof(size_t), 1, taintCache);
    for (int i = 0; i < (int)cacheSize; i++){
        fread(name, 50, 1, taintCache);
        fread(&numBBs, sizeof(int), 1, taintCache);
        filettb = taint_tb_new(name, numBBs);
#ifdef TAINTDEBUG
        printf("reading %s from cache\n", name);
#endif
        fread(&filettb->entry->label, sizeof(((TaintBB*)0)->label), 1,
            taintCache);
        fread(&taintbufsize, sizeof(uint32_t), 1, taintCache);
        filettb->entry->ops = (TaintOpBuffer*)my_malloc(sizeof(TaintOpBuffer),
            poolid_taint_processor);
        filettb->entry->ops->size = taintbufsize;
        filettb->entry->ops->max_size = taintbufsize;
        filettb->entry->ops->start = (char*)my_malloc(taintbufsize,
            poolid_taint_processor);
        fread(filettb->entry->ops->start, taintbufsize, 1, taintCache);

        // read additional BBs if they exist
        if (numBBs > 1){
            for (int j = 0; j < numBBs-1; j++){
                fread(&filettb->tbbs[j]->label, sizeof(((TaintBB*)0)->label), 1,
                    taintCache);
                fread(&taintbufsize, sizeof(uint32_t), 1, taintCache);
                filettb->tbbs[j]->ops = (TaintOpBuffer*)my_malloc(
                    sizeof(TaintOpBuffer), poolid_taint_processor);
                filettb->tbbs[j]->ops->size = taintbufsize;
                filettb->tbbs[j]->ops->max_size = taintbufsize;
                filettb->tbbs[j]->ops->start = (char*)my_malloc(taintbufsize,
                    poolid_taint_processor);
                fread(filettb->tbbs[j]->ops->start, taintbufsize, 1,
                    taintCache);
            }
        }
        
        ttbCache->insert(std::pair<std::string, TaintTB*>(
            std::string(name), filettb));
    }
}

void LaredoTaintFunctionPass::writeTaintCache(){
    std::map<std::string, TaintTB*>::iterator it;
    size_t cacheSize = ttbCache->size();
    fwrite(&cacheSize, sizeof(size_t), 1, taintCache);
    for (it = ttbCache->begin(); it != ttbCache->end(); it++){
#ifdef TAINTDEBUG
        printf("writing %s to cache\n", it->second->name);
#endif
        fwrite(it->second->name, 50, 1, taintCache);
        fwrite(&it->second->numBBs, sizeof(((TaintTB*)0)->numBBs), 1,
            taintCache);
        fwrite(&it->second->entry->label, sizeof(((TaintBB*)0)->label), 1,
            taintCache);
        fwrite(&it->second->entry->ops->size, sizeof(((TaintOpBuffer*)0)->size),
            1, taintCache);
        fwrite(it->second->entry->ops->start, it->second->entry->ops->size, 1,
            taintCache);

        // write additional BBs if they exist
        if (it->second->numBBs > 1){
            for (int i = 0; i < it->second->numBBs-1; i++){
                fwrite(&it->second->tbbs[i]->label,
                    sizeof(((TaintBB*)0)->label), 1, taintCache);
                fwrite(&it->second->tbbs[i]->ops->size,
                    sizeof(((TaintOpBuffer*)0)->size), 1, taintCache);
                fwrite(it->second->tbbs[i]->ops->start,
                    it->second->tbbs[i]->ops->size, 1, taintCache);
            }
        }
    }
}



/***
 *** LaredoSlotTracker
 ***/



LaredoSlotTracker *llvm::createLaredoSlotTracker(Function *F){
    return new LaredoSlotTracker(F);
}

void LaredoSlotTracker::initialize(){
    if (TheFunction && !FunctionProcessed){
        processFunction();
    }
}

void LaredoSlotTracker::processFunction(){
    // Add arguments without names
    for(Function::arg_iterator AI = TheFunction->arg_begin(),
        AE = TheFunction->arg_end(); AI != AE; ++AI){
        if (!AI->hasName()){
            CreateFunctionSlot(AI);
        }
        else {
            AI->setName("");
            CreateFunctionSlot(AI);
        }
    }

    // Add all of the basic blocks and instructions with no names.
    for (Function::iterator BB = TheFunction->begin(),
        E = TheFunction->end(); BB != E; ++BB) {
        if (!BB->hasName()){
            CreateFunctionSlot(BB);
        }
        else {
            // the naming of the 'entry' BB happens by default, so leave it
            if (strcmp(BB->getName().str().c_str(), "entry")){
                BB->setName("");
                CreateFunctionSlot(BB);
            }
        }
        for (BasicBlock::iterator I = BB->begin(), E = BB->end(); I != E; 
            ++I) {
            if (I->getType() != Type::getVoidTy(TheFunction->getContext()) &&
                !I->hasName()){
                CreateFunctionSlot(I);
            }
            else if (I->getType() != Type::getVoidTy(TheFunction->getContext()) 
                && I->hasName()){
                I->setName("");
                CreateFunctionSlot(I);
            }

            // We currently are assuming no metadata, but we will need this if
            // we start using metadata
            /*for (unsigned i = 0, e = I->getNumOperands(); i != e; ++i) {
                if (MDNode *N = dyn_cast_or_null<MDNode>(I->getOperand(i))){
                    CreateMetadataSlot(N);
                }
            }*/
        }
    }
    FunctionProcessed = true;
}

void LaredoSlotTracker::CreateFunctionSlot(const Value *V){
    assert(V->getType() != Type::getVoidTy(TheFunction->getContext()) && 
        !V->hasName() && "Doesn't need a slot!");
    unsigned DestSlot = fNext++;
    fMap[V] = DestSlot;
}

//void LaredoSlotTracker::CreateMetadataSlot(const MDNode *N){
    // don't currently need this, but we will if we start using metadata
//}

int LaredoSlotTracker::getLocalSlot(const Value *V){
    ValueMap::iterator FI = fMap.find(V);
    return FI == fMap.end() ? -1 : (int)FI->second; 
}



/***
 *** LaredoTaintVisitor
 ***/



/*
 * Returns size in bytes of a generic LLVM value (could be operand or
 * instruction).
 */
int LaredoTaintVisitor::getValueSize(Value *V){
    if (V->getType()->isIntegerTy()){
        return ceil(V->getType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isPointerTy()){
        return ceil(static_cast<SequentialType*>(V->getType())->
            getElementType()->getScalarSizeInBits() / 8.0);
    }
    else {
        // those are all that's supported for now
        assert(1==0);
        return -1;
    }
}

// Delete taint at destination LLVM register
void LaredoTaintVisitor::simpleDeleteTaintAtDest(int llvmReg){
    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = llvmReg;
    for (int i = 0; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, op);
    }
}

// Copy taint from LLVM source to dest byte by byte
void LaredoTaintVisitor::simpleTaintCopy(int source, int dest, int bytes){
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    dst.val.la = dest;
    src.typ = LADDR;
    src.val.la = source;

    for (int i = 0; i < bytes; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, op);
    }
}

// Compute operations, byte by byte
void LaredoTaintVisitor::simpleTaintCompute(int source0, AddrType source0ty,
        int source1, AddrType source1ty, int dest, int bytes){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    dst.typ = LADDR;
    dst.val.la = dest;
    src0.typ = source0ty;
    src0.val.la = source0;
    src1.typ = source1ty;
    src1.val.la = source1;

    for (int i = 0; i < bytes; i++){
        src0.off = i;
        src1.off = i;
        dst.off = i;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);
    }
}

// Deals with taint ops for inttoptr and ptrtoint instructions
void LaredoTaintVisitor::intPtrHelper(Instruction &I, int sourcesize, int destsize){
    
    // If the sizes are equal, then it is a series of simple copy operations
    if (sourcesize == destsize){
        simpleTaintCopy(LST->getLocalSlot(I.getOperand(0)),
            LST->getLocalSlot(&I), destsize);
    }

    // If the destination is smaller than the source, then copy the least
    // significant bytes, and delete taint at the most significant
    else if (sourcesize > destsize){
        simpleTaintCopy(LST->getLocalSlot(I.getOperand(0)),
            LST->getLocalSlot(&I), destsize);
        
        struct taint_op_struct op = {};
        struct addr_struct dst = {};
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = destsize; i < MAXREGSIZE; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }

    // If the source is smaller than the destination, then copy the least
    // significant bytes, and delete taint at the bytes that are zero-extended
    else if (sourcesize < destsize){
        simpleTaintCopy(LST->getLocalSlot(I.getOperand(0)),
            LST->getLocalSlot(&I), sourcesize);
        
        // delete taint on extra bytes
        struct taint_op_struct op = {};
        struct addr_struct dst = {};
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = sourcesize; i < MAXREGSIZE; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }

    else {
        printf("Error: PtrToIntInst/IntToPtrInst size error\n");
        assert(1==0);
    }
}

// Deals with taint ops for integer add and subtract instructions
void LaredoTaintVisitor::addSubHelper(Value *arg0, Value *arg1, Value *dstval){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = LST->getLocalSlot(arg0);
    int operand1 = LST->getLocalSlot(arg1);
    int size = ceil(arg0->getType()->getScalarSizeInBits() / 8.0);

    // result gets taint from each source
    if (!isa<Constant>(arg0) && !isa<Constant>(arg1)){


        /**** TEST ****/
        // label operand0
        /*Addr a;
        TaintOp op2;
        op2.typ = LABELOP;
        a.typ = LADDR;
        a.val.la = operand0;
        a.off = 0;
        op2.val.label.l = 0;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);*/
        /**** TEST ****/



        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(ci-1, ai, ci)
        // compute(bi, ci, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = LST->getLocalSlot(dstval);
            src1.val.la = operand0;
            dst.val.la = LST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);

            src0.val.la = operand1;
            src1.val.la = LST->getLocalSlot(dstval);
            dst.val.la = LST->getLocalSlot(dstval);
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    // we don't actually care what the constant is for now
    // result gets taint from LLVM register source operand
    else if (isa<Constant>(arg0)){
        // compute(a0, b0, c0)
        src0.typ = CONST;
        src0.val.con = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(ci-1, bi, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = LST->getLocalSlot(dstval);
            src1.val.la = operand1;
            src1.typ = LADDR;
            dst.val.la = LST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    else if (isa<Constant>(arg1)){


        /**** TEST ****/
        // label operand0
        /*Addr a;
        TaintOp op2;
        op2.typ = LABELOP;
        a.typ = LADDR;
        a.val.la = operand0;
        a.off = 0;
        op2.val.label.l = 0;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);*/
        /**** TEST ****/

        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = CONST;
        src1.val.con = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(ci-1, ai, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = LST->getLocalSlot(dstval);
            src1.val.la = operand0;
            src1.typ = LADDR;
            dst.val.la = LST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(arg0) && isa<Constant>(arg1)){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(dstval);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }

    else {
        assert(1==0);
    }
}

// Deals with taint ops for integer multiply instructions
void LaredoTaintVisitor::mulHelper(BinaryOperator &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = LST->getLocalSlot(I.getOperand(0));
    int operand1 = LST->getLocalSlot(I.getOperand(1));
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    // result gets taint from each source
    if (!isa<Constant>(I.getOperand(0)) && !isa<Constant>(I.getOperand(1))){


        /**** TEST ****/
        // label operand0
        /*Addr a;
        TaintOp op2;
        op2.typ = LABELOP;
        a.typ = LADDR;
        a.val.la = operand0;
        a.off = 0;
        op2.val.label.l = 0;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);*/
        /**** TEST ****/




        // accumulate all of a's taint into c0
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand0;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }

        // compute(a0, c0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = LST->getLocalSlot(&I);
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(b0, c0, c0)
        src0.val.la = operand1;
        op.val.compute.a = src0;
        tob_op_write(tbuf, op);

        // compute(ci-1, ai, ci)
        // compute(bi, ci, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = LST->getLocalSlot(&I);
            src1.val.la = operand0;
            dst.val.la = LST->getLocalSlot(&I);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);

            src0.val.la = operand1;
            src1.val.la = LST->getLocalSlot(&I);
            dst.val.la = LST->getLocalSlot(&I);
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    // we don't actually care what the constant is for now
    // result gets taint from LLVM register source operand
    // this is similar to the taint model for add
    else if (isa<Constant>(I.getOperand(0))){
        // compute(a0, b0, c0)
        src0.typ = CONST;
        src0.val.con = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(ci-1, bi, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = LST->getLocalSlot(&I);
            src1.val.la = operand1;
            src1.typ = LADDR;
            dst.val.la = LST->getLocalSlot(&I);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    else if (isa<Constant>(I.getOperand(1))){


        /**** TEST ****/
        // label operand0
        /*Addr a;
        TaintOp op2;
        op2.typ = LABELOP;
        a.typ = LADDR;
        a.val.la = operand0;
        a.off = 0;
        op2.val.label.l = 0;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);*/
        /**** TEST ****/

        // accumulate all of a's taint into c0
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand0;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = LST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }

    else {
        assert(1==0);
    }
}

/*
 * XXX: Broken.  If you want a more accurate shift model, fix this.
 */
void LaredoTaintVisitor::shiftHelper(BinaryOperator &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = LST->getLocalSlot(I.getOperand(0));
    int operand1 = LST->getLocalSlot(I.getOperand(1));
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    // apply each byte of taint from shift amount to each byte of destination,
    // then copy taint of each byte of source op to each byte of dest through
    // compute ops
    if (!isa<Constant>(I.getOperand(0)) && !isa<Constant>(I.getOperand(1))){
        // accumulate all of b's taint into c0
        src0.typ = LADDR;
        src0.val.la = operand1;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = LST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }

        // copy each byte of operand 0 to each byte of destination through
        // compute ops
        src0.val.la = operand0;
        src1.val.la = LST->getLocalSlot(&I);
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }
    
    // we don't actually care what the constant is for now
    // each result byte gets taint of each byte of shift amount
    else if (isa<Constant>(I.getOperand(0))){
        // accumulate all of b's taint into c0
        src0.typ = LADDR;
        src0.val.la = operand1;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = LST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }
    
    // for now, copy taint to each destination byte through compute ops
    else if (isa<Constant>(I.getOperand(1))){
        src0.typ = LADDR;
        src0.val.la = operand0;
        src1.typ = LADDR;
        src1.val.la = operand0;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = LST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }
    
    else {
        assert(1==0);
    }
}

/*
 * Applies union of each byte of each operand to each byte of result
 */
void LaredoTaintVisitor::approxArithHelper(BinaryOperator &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);
    int constantArgs = 0;

    // Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = LST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, op);

    for (int oper = 0; oper < 2; oper++){
        // Operand is a constant, therefore it can't be tainted
        if (LST->getLocalSlot(I.getOperand(oper)) < 0){
            constantArgs++;

            // both args were constants, need to delete taint
            if (constantArgs == 2){
                op.typ = DELETEOP;
                dst.typ = LADDR;
                dst.val.la = LST->getLocalSlot(&I);
                for (int i = 0; i < size; i++){
                    dst.off = i;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, op);
                }
                return;
            }

            continue;
        }

        // accumulate all of oper[i]'s taint into c0 of temp
        op.typ = COMPUTEOP;
        src0.typ = LADDR;
        src0.val.la = LST->getLocalSlot(I.getOperand(oper));
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = LST->getLocalSlot(&I)+1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I) + 1;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;

        for (int i = 0; i < size; i++){
            src0.off = i;
            op.val.compute.a = src0;
            tob_op_write(tbuf, op);
        }
    }
    
    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = LST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = LST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = LST->getLocalSlot(&I);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);
    }
}

// Currently only used for and, or, and xor
void LaredoTaintVisitor::simpleArithHelper(BinaryOperator &I){
    int source0 = LST->getLocalSlot(I.getOperand(0));
    AddrType source0ty = isa<Constant>(I.getOperand(0)) ? CONST : LADDR;
    int source1 = LST->getLocalSlot(I.getOperand(1));
    AddrType source1ty = isa<Constant>(I.getOperand(1)) ? CONST : LADDR;
    int dest = LST->getLocalSlot(&I);
    int bytes = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    simpleTaintCompute(source0, source0ty, source1, source1ty, dest, bytes);
}

// Terminator instructions
void LaredoTaintVisitor::visitReturnInst(ReturnInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};

    // need to copy taint to return register if it returns a value
    int result = LST->getLocalSlot(I.getReturnValue());
    if (result > -1){
        src.typ = LADDR;
        src.val.la = result;
        dst.typ = RET;
        op.typ = COPYOP;
        for (int i = 0; i < getValueSize(I.getReturnValue()); i++){
            src.off = i;
            dst.off = i;
            op.val.copy.a = src;
            op.val.copy.b = dst;
            tob_op_write(tbuf, op);
        }
    }
    
    op.typ = RETOP;
    tob_op_write(tbuf, op);
}

void LaredoTaintVisitor::visitBranchInst(BranchInst &I){
    // write instruction boundary op
    struct taint_op_struct op = {};
    op.typ = INSNSTARTOP;
    char name[11] = "condbranch";
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = 0;
    op.val.insn_start.flag = INSNREADLOG;
    for (int i = 0; i < (int)I.getNumSuccessors(); i++){
        op.val.insn_start.branch_labels[i] =
            LST->getLocalSlot(I.getSuccessor(i));
    }
    tob_op_write(tbuf, op);
}

void LaredoTaintVisitor::visitSwitchInst(SwitchInst &I){}
void LaredoTaintVisitor::visitIndirectBrInst(IndirectBrInst &I){}
void LaredoTaintVisitor::visitInvokeInst(InvokeInst &I){}
void LaredoTaintVisitor::visitResumeInst(ResumeInst &I){}
void LaredoTaintVisitor::visitUnwindInst(UnwindInst &I){}
void LaredoTaintVisitor::visitUnreachableInst(UnreachableInst &I){}

// Binary operators
void LaredoTaintVisitor::visitBinaryOperator(BinaryOperator &I){
    switch (I.getOpcode()){

        case Instruction::Add:
            addSubHelper(I.getOperand(0), I.getOperand(1), &I);
            //simpleArithHelper(I);
            break;

        case Instruction::FAdd:
            break;
        
        case Instruction::Sub:
            addSubHelper(I.getOperand(0), I.getOperand(1), &I);
            //simpleArithHelper(I);
            break;

        case Instruction::FSub:
            break;

        case Instruction::Mul:
            //mulHelper(I);
            //simpleArithHelper(I);
            approxArithHelper(I);
            break;

        case Instruction::FMul:
            break;

        case Instruction::UDiv:
            approxArithHelper(I);
            break;

        case Instruction::SDiv:
            approxArithHelper(I);
            break;

        case Instruction::FDiv:
            break;

        case Instruction::URem:
            approxArithHelper(I);
            break;

        case Instruction::SRem:
            approxArithHelper(I);
            break;
        
        case Instruction::FRem:
            break;
        
        case Instruction::Shl:
            //shiftHelper(I);
            //simpleArithHelper(I);

            /*
             * FIXME: Hack to account for some constant operands and propagating
             * taint more precisely.  Make this more generic when we have more
             * time.
             */
            if ((!isa<Constant>(I.getOperand(0)))
                && (isa<Constant>(I.getOperand(1)))
                && (getValueSize(&I) == 8)){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                if (con == 56){
                    //printf("hacked shl\n");
                    int srcval = LST->getLocalSlot(I.getOperand(0));
                    int dstval = LST->getLocalSlot(&I);
                    struct taint_op_struct op = {};
                    struct addr_struct src = {};
                    struct addr_struct dst = {};
                    op.typ = COPYOP;
                    src.typ = LADDR;
                    dst.typ = LADDR;
                    src.off = 0;
                    dst.off = 7;
                    src.val.la = srcval;
                    dst.val.la = dstval;
                    op.val.copy.a = src;
                    op.val.copy.b = dst;
                    tob_op_write(tbuf, op);

                    op.typ = DELETEOP;
                    for (int i = 0; i < 7; i++){
                        dst.off = i;
                        op.val.deletel.a = dst;
                        tob_op_write(tbuf, op);
                    }
                }
                else {
                    approxArithHelper(I);
                }
            }
            else {
                approxArithHelper(I);
            }
            break;

        case Instruction::LShr:
            //shiftHelper(I);
            //simpleArithHelper(I);

            /*
             * FIXME: Hack to account for some constant operands.  Make this
             * more generic when we have more time.
             */
            if ((!isa<Constant>(I.getOperand(0)))
                && (isa<Constant>(I.getOperand(1)))
                && (getValueSize(&I) == 8)){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                if ((con > 0) && (con <= 8)){
                    //printf("hacked lshr\n");
                    int srcval = LST->getLocalSlot(I.getOperand(0));
                    int dstval = LST->getLocalSlot(&I);
                    struct taint_op_struct op = {};
                    struct addr_struct src = {};
                    struct addr_struct dst = {};
                    op.typ = COPYOP;
                    src.typ = LADDR;
                    dst.typ = LADDR;
                    src.val.la = srcval;
                    dst.val.la = dstval;
                    for (int i = 1; i < 8; i++){
                        src.off = i;
                        dst.off = i-1;
                        op.val.copy.a = src;
                        op.val.copy.b = dst;
                        tob_op_write(tbuf, op);
                    }

                    op.typ = DELETEOP;
                    dst.off = 7;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, op);
                }
                else if ((con >= 56) && (con < 64)){
                    //printf("hacked lshr\n");
                    int srcval = LST->getLocalSlot(I.getOperand(0));
                    int dstval = LST->getLocalSlot(&I);
                    struct taint_op_struct op = {};
                    struct addr_struct src = {};
                    struct addr_struct dst = {};
                    op.typ = COPYOP;
                    src.typ = LADDR;
                    dst.typ = LADDR;
                    src.off = 7;
                    dst.off = 0;
                    src.val.la = srcval;
                    dst.val.la = dstval;
                    op.val.copy.a = src;
                    op.val.copy.b = dst;
                    tob_op_write(tbuf, op);

                    op.typ = DELETEOP;
                    for (int i = 1; i < 8; i++){
                        dst.off = i;
                        op.val.deletel.a = dst;
                        tob_op_write(tbuf, op);
                    }
                }
                else {
                    approxArithHelper(I);
                }
            }
            else {
                approxArithHelper(I);
            }
            break;

        case Instruction::AShr:
            //shiftHelper(I);
            //simpleArithHelper(I);
            approxArithHelper(I);
            break;

        case Instruction::And:
            // TODO: think about more precise propagation when we have constants
            // on hand.  this goes for shift also.
            if (isa<Constant>(I.getOperand(1))){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                int srcval = LST->getLocalSlot(I.getOperand(0));
                int dstval = LST->getLocalSlot(&I);
                //printf("%lu\n", con);
                if ((con > 0) && (con <= 255)){
                    simpleTaintCopy(srcval, dstval, 1);
                    
                    // delete taint on extra bytes
                    struct taint_op_struct op = {};
                    struct addr_struct dst = {};
                    op.typ = DELETEOP;
                    dst.typ = LADDR;
                    dst.val.la = dstval;
                    for (int i = 1; i < MAXREGSIZE; i++){
                        dst.off = i;
                        op.val.deletel.a = dst;
                        tob_op_write(tbuf, op);
                    }
                }
                else {
                    simpleArithHelper(I);
                }
            }
            else {
                simpleArithHelper(I);
            }
            simpleArithHelper(I);
            break;

        case Instruction::Or:
            simpleArithHelper(I);
            break;

        case Instruction::Xor:
            simpleArithHelper(I);
            break;

        default:
            printf("Unknown binary operator\n");
            exit(1);
    }
}

// Memory operators

// Delete taint at destination register
void LaredoTaintVisitor::visitAllocaInst(AllocaInst &I){
    simpleDeleteTaintAtDest(LST->getLocalSlot(&I));
}

void LaredoTaintVisitor::loadHelper(Value *srcval, Value *dstval, int len){
    // local is LLVM register destination of load
    int local = LST->getLocalSlot(dstval);
    
    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[5] = "load";

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = len;
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, op);

    // write taint ops
    op.typ = COPYOP;
    dst.typ = LADDR;
    src.typ = UNK;
    src.val.ua = 0;
    src.flag = READLOG;
    dst.val.la = local;

    for (int i = 0; i < len; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, op);
    }

#ifdef TAINTED_POINTER
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};

    // Pointer is a constant, therefore it can't be tainted
    if (LST->getLocalSlot(srcval) < 0){
        //printf("CONSTANT\n");
        return;
    }

    // accumulate all of b's taint into one byte of temp register
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = LST->getLocalSlot(srcval);
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = LST->getLocalSlot(srcval);
    src1.off = 0;
    dst.typ = RET;
    dst.off = 0;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;
    tob_op_write(tbuf, op);

    src1.typ = RET;
    op.val.compute.b = src1;
    for (int i = 1; i < len; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, op);
    }

    // propagate accumulated taint in temp[0] to all result bytes
    src0.typ = RET;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = LST->getLocalSlot(dstval);
    src1.typ = LADDR;
    dst.val.la = LST->getLocalSlot(dstval);
    dst.typ = LADDR;
    for (int i = 0; i < len; i++){
        src1.off = i;
        dst.off = i;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);
    }
#endif 
}

void LaredoTaintVisitor::visitLoadInst(LoadInst &I){
    /*
     * For source code analysis, loading a global value is likely the root
     * pointer of CPUState or a pointer for something inside of it, therefore it
     * isn't tainted.
     */
    if (isa<GlobalValue>(I.getPointerOperand())){
        simpleDeleteTaintAtDest(LST->getLocalSlot(&I));
        return;
    }
    
    // get source operand length
    int len = ceil(static_cast<SequentialType*>(I.getOperand(0)->
        getType())->getElementType()->getScalarSizeInBits() / 8.0);
    loadHelper(I.getOperand(0), &I, len);
}

void LaredoTaintVisitor::storeHelper(Value *srcval, Value *dstval, int len){
    // can't propagate taint from a constant
    bool srcConstant = isa<Constant>(srcval);

    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[6] = "store";

    // delete taint in temp[0] for use later on
    op.typ = DELETEOP;
    dst.typ = RET;
    dst.off = 0;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, op);

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
#if !defined(TAINTED_POINTER)
    op.val.insn_start.num_ops = len;
#elif defined(TAINTED_POINTER)
    // if pointer is a constant, it can't be tainted so we don't include taint
    // ops to propagate tainted pointer
    if (LST->getLocalSlot(dstval) < 0){
        op.val.insn_start.num_ops = len;
    }
    else {
        // need INSNSTART to fill in tainted pointer ops too
        op.val.insn_start.num_ops = len * 3;
    }
#endif

    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, op);

    if (srcConstant){
        op.typ = DELETEOP;
        dst.typ = UNK;
        dst.val.ua = 0;
        dst.flag = READLOG;
        for (int i = 0; i < len; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, op);
        }
    }
    else {
        op.typ = COPYOP;
        dst.typ = UNK;
        dst.flag = READLOG;
        dst.val.ua = 0;
        src.typ = LADDR;
        src.val.la = LST->getLocalSlot(srcval);
        for (int i = 0; i < len; i++){
            src.off = i;
            dst.off = i;
            op.val.copy.a = src;
            op.val.copy.b = dst;
            tob_op_write(tbuf, op);
        }
    }

#ifdef TAINTED_POINTER
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    
    // Pointer is a constant, therefore it can't be tainted
    if (LST->getLocalSlot(dstval) < 0){
        return;
    }

    // accumulate all of b's taint into temp[0]
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = LST->getLocalSlot(dstval);
    src0.off = 0;
    src1.typ = RET;
    src1.off = 0;
    dst.typ = RET;
    dst.off = 0;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;

    for (int i = 0; i < len; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, op);
    }

    // propagate accumulated taint in temp[0] to all result bytes
    src0.typ = RET;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.typ = UNK;
    dst.typ = UNK;
    for (int i = 0; i < len; i++){
        src1.off = i;
        dst.off = i;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);
    }
#endif
}

/*
 * We should only care about non-volatile stores, the volatile stores are
 * irrelevant to guest execution.  Volatile stores come in pairs for each guest
 * instruction, so we can gather statistics looking at every other volatile
 * store.
 */
bool evenStore = false;
void LaredoTaintVisitor::visitStoreInst(StoreInst &I){

    if (I.isVolatile()){
#ifdef TAINTSTATS
        evenStore = !evenStore;
        if (evenStore){
            dump_taint_stats(shad);
        }
#endif
        return;
    }

    // get source operand length
    int len = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);
    storeHelper(I.getOperand(0), I.getOperand(1), len);
}

void LaredoTaintVisitor::visitFenceInst(FenceInst &I){}
void LaredoTaintVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I){}
void LaredoTaintVisitor::visitAtomicRMWInst(AtomicRMWInst &I){}

/*
 * In TCG->LLVM translation, it seems like this instruction is only used to get
 * the pointer to the CPU state.  Because of this, we will just delete taint at
 * the destination LLVM register.
 */
void LaredoTaintVisitor::visitGetElementPtrInst(GetElementPtrInst &I){
    simpleDeleteTaintAtDest(LST->getLocalSlot(&I));
}

// Cast operators

void LaredoTaintVisitor::visitTruncInst(TruncInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: trunc constant operand (FIXME)\n");
        assert(1==0);
        return;
    }

    int destsize = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    int srcval = LST->getLocalSlot(I.getOperand(0));
    int dstval = LST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, destsize);
    
    // delete taint on extra bytes
    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = LST->getLocalSlot(&I);
    for (int i = destsize; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, op);
    }
}

void LaredoTaintVisitor::visitZExtInst(ZExtInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: zext constant operand (FIXME)\n");
        assert(1==0);
        return;
    }
    
    int sourcesize = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() /
        8.0);
    int srcval = LST->getLocalSlot(I.getOperand(0));
    int dstval = LST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, sourcesize);

    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = LST->getLocalSlot(&I);
    for (int i = sourcesize; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, op);
    }
}

void LaredoTaintVisitor::visitSExtInst(SExtInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: sext constant operand (FIXME)\n");
        assert(1==0);
        return;
    }
    int sourcesize = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() /
        8.0);
    int destsize = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    int srcval = LST->getLocalSlot(I.getOperand(0));
    int dstval = LST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, sourcesize);
    
    // apply compute taint to sign-extended bytes
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    src0.typ = src1.typ = dst.typ = LADDR;
    src0.val.la = src1.val.la = LST->getLocalSlot(I.getOperand(0));
    dst.val.la = LST->getLocalSlot(&I);
    for (int i = sourcesize; i < destsize; i++){
        src0.off = sourcesize - 1;
        src1.off = sourcesize - 1;
        dst.off = i;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);
    }
}

void LaredoTaintVisitor::visitFPToUIInst(FPToUIInst &I){}
void LaredoTaintVisitor::visitFPToSIInst(FPToSIInst &I){}
void LaredoTaintVisitor::visitUIToFPInst(UIToFPInst &I){}
void LaredoTaintVisitor::visitSIToFPInst(SIToFPInst &I){}
void LaredoTaintVisitor::visitFPTruncInst(FPTruncInst &I){}
void LaredoTaintVisitor::visitFPExtInst(FPExtInst &I){}

void LaredoTaintVisitor::visitPtrToIntInst(PtrToIntInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: ptrtoint constant operand (FIXME)\n");
        assert(1==0);
        return;
    }
    int sourcesize =
        ceil(static_cast<SequentialType*>(I.getOperand(0)->getType())->
        getElementType()->getScalarSizeInBits() / 8.0);
    int destsize = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    intPtrHelper(I, sourcesize, destsize);
}

void LaredoTaintVisitor::visitIntToPtrInst(IntToPtrInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: inttoptr constant operand (FIXME)\n");
        assert(1==0);
        return;
    }
    int sourcesize = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() /
        8.0);
    int destsize = ceil(static_cast<SequentialType*>(I.getType())->
        getElementType()->getScalarSizeInBits() / 8.0);
    intPtrHelper(I, sourcesize, destsize);
}

/*
 * Haven't actually seen bitcast in generated code, we've only seen it in helper
 * functions for pointer operations in QEMU address space.  We treat it the same
 * way as getelementptr, and delete taint.  This may need to change if it is
 * used in other ways.
 */
void LaredoTaintVisitor::visitBitCastInst(BitCastInst &I){
    simpleDeleteTaintAtDest(LST->getLocalSlot(&I));
}

// Other operators

/*
 * If both operands are LLVM registers, then the result will be a one bit (byte)
 * compute taint.  If only one operand is a register, then the result will be a
 * compute, but only propagating taint from the register source.  If both are
 * constants, then it will be a delete.  Since this is usually used for a branch
 * condition, this could let us see if we can
 * potentially affect control flow.
 */
void LaredoTaintVisitor::visitICmpInst(ICmpInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = LST->getLocalSlot(I.getOperand(0));
    int operand1 = LST->getLocalSlot(I.getOperand(1));
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    // result byte gets union of each source byte
    if (!isa<Constant>(I.getOperand(0)) && !isa<Constant>(I.getOperand(1))){
        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(c0, ai, c0)
        // compute(c0, bi, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src1.off = i;
            src1.val.la = operand0;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
            src1.val.la = operand1;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }
    }

    // we don't actually care what the constant is for now
    // result byte gets union of bytes in LLVM register source operand
    else if (isa<Constant>(I.getOperand(0))){
        // compute(a0, b0, c0)
        src0.typ = CONST;
        src0.val.con = 0;
        src1.typ = LADDR;
        src1.val.la = operand1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(c0, bi, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, op);
        }
    }

    else if (isa<Constant>(I.getOperand(1))){


        /**** TEST ****/
        // label operand0
        /*Addr a;
        TaintOp op2;
        op2.typ = LABELOP;
        a.typ = LADDR;
        a.val.la = operand0;
        a.off = 0;
        op2.val.label.l = 0;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, op2);*/
        /**** TEST ****/

        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = CONST;
        src1.val.con = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, op);

        // compute(c0, ai, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src0.off = i;
            op.val.compute.b = src0;
            tob_op_write(tbuf, op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = LST->getLocalSlot(&I);
        op.val.deletel.a = dst;
        tob_op_write(tbuf, op);
    }

    else {
        assert(1==0);
    }
}

void LaredoTaintVisitor::visitFCmpInst(FCmpInst &I){}
void LaredoTaintVisitor::visitPHINode(PHINode &I){}

/*
 * Taint model for LLVM bswap intrinsic.
 */
void LaredoTaintVisitor::bswapHelper(CallInst &I){
    int bytes = getValueSize(&I);
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    dst.val.la = LST->getLocalSlot(&I);
    src.typ = LADDR;
    src.val.la = LST->getLocalSlot(I.getArgOperand(0));
    
    for (int i = 0; i < bytes; i++){
        src.off = i;
        dst.off = bytes-i-1;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, op);
    }
}

void LaredoTaintVisitor::visitCallInst(CallInst &I){
    Function *called = I.getCalledFunction();
    if (!called) {
        assert(1==0);
        return; // doesn't have name, we can't process it
    }
    std::string calledName = called->getName().str();
    
    // Check to see if it's a supported intrinsic
    if (I.getCalledFunction()->getIntrinsicID()
            == Intrinsic::uadd_with_overflow){
        addSubHelper(I.getArgOperand(0), I.getArgOperand(1), &I);
        return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::bswap){
        bswapHelper(I);
        return;
    }
    else if (I.getCalledFunction()->getIntrinsicID()
            != Intrinsic::not_intrinsic){
        printf("Error: unsupported intrinsic\n");
        assert(1==0);
    }
    else if (!calledName.compare("__ldb_mmu_panda")
            || !calledName.compare("__ldw_mmu_panda")
            || !calledName.compare("__ldl_mmu_panda")
            || !calledName.compare("__ldq_mmu_panda")
            || !calledName.compare("__ldq_mmu_panda")){

        // guest load in whole-system mode
        int len = getValueSize(&I);
        loadHelper(I.getArgOperand(0), &I, len);
        return;
    }
    else if (!calledName.compare("__stb_mmu_panda")
            || !calledName.compare("__stw_mmu_panda")
            || !calledName.compare("__stl_mmu_panda")
            || !calledName.compare("__stq_mmu_panda")
            || !calledName.compare("__stq_mmu_panda")){

        // guest store in whole-system mode
        int len = getValueSize(I.getArgOperand(1));
        storeHelper(I.getArgOperand(1), I.getArgOperand(0), len);
        return;
    }

    // Ignore instrumentation functions
    else if (!strcmp(calledName.c_str(), "printdynval")
            || !strcmp(calledName.c_str(), "printramaddr")){
        return;
    }

    std::map<std::string, TaintTB*>::iterator it = ttbCache->find(calledName);
    if (it != ttbCache->end()){
#ifdef TAINTDEBUG
        printf("found %s in cache\n", it->first.c_str());
#endif
        /*** Process call taint here ***/
        
        struct taint_op_struct op = {};
        struct addr_struct src = {};
        struct addr_struct dst = {};
        src.typ = LADDR;
        dst.typ = LADDR;
        dst.flag = FUNCARG; // copy taint to new frame
        int argBytes;

        // if there are args then copy their taint to new frame
        int numArgs = I.getNumArgOperands();
        for (int i = 0; i < numArgs; i++){
            Value *arg = I.getArgOperand(i);
            argBytes = getValueSize(arg);

            // if arg is constant then delete taint in arg reg
            if (isa<Constant>(arg)){
                op.typ = DELETEOP;
                dst.val.la = i;
                for (int j = 0; j < argBytes; j++){
                    dst.off = j;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, op);
                }
            }
            else {
                op.typ = COPYOP;
                src.val.la = LST->getLocalSlot(arg);
                dst.val.la = i;
                for (int j = 0; j < argBytes; j++){
                    src.off = j;
                    dst.off = j;
                    op.val.copy.a = src;
                    op.val.copy.b = dst;
                    tob_op_write(tbuf, op);
                }
            }
        }

        // call op (function name, pointer to taint buf, increment frame level)
        op.typ = CALLOP;
        strncpy(op.val.call.name, it->first.c_str(), FUNCNAMELENGTH);
        op.val.call.ttb = it->second;
        tob_op_write(tbuf, op);

        // copy return reg to value in this frame, if applicable
        int slot = LST->getLocalSlot(&I);
        if (slot > -1){
            op.typ = COPYOP;
            memset(&src, 0, sizeof(src));
            memset(&dst, 0, sizeof(dst));
            src.typ = RET;
            dst.typ = LADDR;
            dst.val.la = slot;
            for (int i = 0; i < getValueSize(&I); i++){
                src.off = i;
                dst.off = i;
                op.val.copy.a = src;
                op.val.copy.b = dst;
                tob_op_write(tbuf, op);
            }
        }
    }
    else {
#ifdef TAINTDEBUG
        printf("didn't find %s in cache\n", calledName.c_str());
#endif
        // if it's not in the cache, ignore taint operations
        return;
    }
}

/*
 * This may need to become more complex for more complex cases of this
 * instruction. Currently we are just treating it like a branch, but with values
 * filled in instead of branch targets.
 */
void LaredoTaintVisitor::visitSelectInst(SelectInst &I){
    // write instruction boundary op
    struct taint_op_struct op = {};
    op.typ = INSNSTARTOP;
    char name[7] = "select";
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    int srcbytelen = getValueSize(&I);
    op.val.insn_start.num_ops = srcbytelen;
    op.val.insn_start.flag = INSNREADLOG;
    op.val.insn_start.branch_labels[0] = LST->getLocalSlot(I.getTrueValue());
    op.val.insn_start.branch_labels[1] = LST->getLocalSlot(I.getFalseValue());
    tob_op_write(tbuf, op);

    // write taint ops
    memset(&op, 0, sizeof(op));
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    src.typ = UNK;
    src.val.ua = 0;
    src.flag = READLOG;
    dst.val.la = LST->getLocalSlot(&I);

    for (int i = 0; i < srcbytelen; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, op);
    }
}

void LaredoTaintVisitor::visitVAArgInst(VAArgInst &I){}
void LaredoTaintVisitor::visitExtractElementInst(ExtractElementInst &I){}
void LaredoTaintVisitor::visitInsertElementInst(InsertElementInst &I){}
void LaredoTaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I){}

/*
 * This may need to become more complex for more complex cases of this
 * instruction.
 */
void LaredoTaintVisitor::visitExtractValueInst(ExtractValueInst &I){
    int src = LST->getLocalSlot(I.getAggregateOperand());
    int dst = LST->getLocalSlot(&I);
    int bytes = getValueSize(&I);
    simpleTaintCopy(src, dst, bytes);
}

void LaredoTaintVisitor::visitInsertValueInst(InsertValueInst &I){}
void LaredoTaintVisitor::visitLandingPadInst(LandingPadInst &I){}

// Unhandled
void LaredoTaintVisitor::visitInstruction(Instruction &I){
    printf("Error: Unhandled instruction\n");
    assert(1==0);
}



/***
 *** LaredoInstrFunctionPass
 ***/



char LaredoInstrFunctionPass::ID = 0;
static RegisterPass<LaredoInstrFunctionPass>
Y("LaredoInstr", "Instrument instructions that produce dynamic values");

FunctionPass *llvm::createLaredoInstrFunctionPass(Module *M) {
    return new LaredoInstrFunctionPass(M);
}

bool LaredoInstrFunctionPass::runOnFunction(Function &F){
    LIV->visit(F);
    return true;
}



/***
 *** LaredoInstrumentVisitor
 ***/



/*
 * Call the logging function, logging the address of the load.  If it's loading
 * the root of a global value (likely CPUState), then we can ignore it.
 */
void LaredoInstrumentVisitor::visitLoadInst(LoadInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (!(isa<GlobalValue>(I.getPointerOperand()))){
        if (isa<Constant>(static_cast<Instruction*>(
                I.getPointerOperand())->getOperand(0))){
            /*
             * Loading from a constant looks something like this:
             * load i32* inttoptr (i64 135193036 to i32*), sort of like an
             * inttoptr instruction as an operand.  This is how we deal with
             * logging that weirdness.
             */
            CallInst *CI;
            std::vector<Value*> argValues;
            uint64_t constaddr = static_cast<ConstantInt*>(
                static_cast<Instruction*>(
                    I.getPointerOperand())->getOperand(0))->getZExtValue();
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
            argValues.push_back(ConstantInt::get(intType, LOAD));
            argValues.push_back(ConstantInt::get(wordType, constaddr));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
        }
        else {
            PtrToIntInst *PTII;
            CallInst *CI;
            std::vector<Value*> argValues;
            PTII = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
                I.getPointerOperand(), wordType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
            argValues.push_back(ConstantInt::get(intType, LOAD));
            argValues.push_back(static_cast<Value*>(PTII));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
            PTII->insertBefore(static_cast<Instruction*>(CI));
        }
    }
}

// Call the logging function, logging the address of the store
void LaredoInstrumentVisitor::visitStoreInst(StoreInst &I){
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.isVolatile()){
        // Stores to LLVM runtime that we don't care about
        return;
    }
    else if (isa<Constant>(static_cast<Instruction*>(
                I.getPointerOperand())->getOperand(0))){
        /*
         * Storing to a constant looks something like this:
         * store i32 %29, i32* inttoptr (i64 135186980 to i32*),
         * sort of like an inttoptr instruction as an operand.  This is how we
         * deal with logging that weirdness.
         */
        CallInst *CI;
        std::vector<Value*> argValues;
        uint64_t constaddr = static_cast<ConstantInt*>(
            static_cast<Instruction*>(
                I.getPointerOperand())->getOperand(0))->getZExtValue();
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, STORE));
        argValues.push_back(ConstantInt::get(wordType, constaddr));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
    else {
        PtrToIntInst *PTII;
        CallInst *CI;
        std::vector<Value*> argValues;
        PTII = static_cast<PtrToIntInst*>(IRB.CreatePtrToInt(
            I.getPointerOperand(), wordType));
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, ADDRENTRY));
        argValues.push_back(ConstantInt::get(intType, STORE));
        argValues.push_back(static_cast<Value*>(PTII));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
        PTII->insertBefore(static_cast<Instruction*>(CI));
    }
}

/*
 * Call the logging function, logging the branch target.  Target[0] is the true
 * branch, and target[1] is the false branch.  So when logging, we NOT the
 * condition to actually log the target taken.  We are also logging and
 * processing unconditional branches for the time being.
 */
void LaredoInstrumentVisitor::visitBranchInst(BranchInst &I){
    BinaryOperator *BO;
    ZExtInst *ZEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Value *condition;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    if (I.isConditional()){
        condition = I.getCondition();
        if (isa<Constant>(condition)){
            CallInst *CI;
            std::vector<Value*> argValues;
            uint64_t constcond = static_cast<ConstantInt*>(
                I.getCondition())->getZExtValue();
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
            argValues.push_back(ConstantInt::get(intType, BRANCHOP));
            argValues.push_back(ConstantInt::get(wordType, !constcond));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
        }
        else {
            BO = static_cast<BinaryOperator*>(IRB.CreateNot(condition));
            ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(BO, wordType));
            argValues.push_back(ConstantInt::get(ptrType,
                (uintptr_t)dynval_buffer));
            argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
            argValues.push_back(ConstantInt::get(intType, BRANCHOP));
            argValues.push_back(static_cast<Value*>(ZEI));
            CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
            CI->insertBefore(static_cast<Instruction*>(&I));
            ZEI->insertBefore(static_cast<Instruction*>(CI));
            BO->insertBefore(static_cast<Instruction*>(ZEI));
        }
    }
    else {
        argValues.push_back(ConstantInt::get(ptrType,
            (uintptr_t)dynval_buffer));
        argValues.push_back(ConstantInt::get(intType, BRANCHENTRY));
        argValues.push_back(ConstantInt::get(intType, BRANCHOP));
        argValues.push_back(ConstantInt::get(wordType, 0));
        CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
        CI->insertBefore(static_cast<Instruction*>(&I));
    }
}

/*
 * Instrument select instructions similar to how we instrument branches.
 */
void LaredoInstrumentVisitor::visitSelectInst(SelectInst &I){
    BinaryOperator *BO;
    ZExtInst *ZEI;
    CallInst *CI;
    std::vector<Value*> argValues;
    Value *condition;
    Function *F = mod->getFunction("log_dynval");
    if (!F) {
        printf("Instrumentation function not found\n");
        assert(1==0);
    }
    condition = I.getCondition();
    BO = static_cast<BinaryOperator*>(IRB.CreateNot(condition));
    ZEI = static_cast<ZExtInst*>(IRB.CreateZExt(BO, wordType));
    argValues.push_back(ConstantInt::get(ptrType,
        (uintptr_t)dynval_buffer));
    argValues.push_back(ConstantInt::get(intType, SELECTENTRY));
    argValues.push_back(ConstantInt::get(intType, SELECT));
    argValues.push_back(static_cast<Value*>(ZEI));
    CI = IRB.CreateCall(F, ArrayRef<Value*>(argValues));
    CI->insertBefore(static_cast<Instruction*>(&I));
    ZEI->insertBefore(static_cast<Instruction*>(CI));
    BO->insertBefore(static_cast<Instruction*>(ZEI));
}

/*
 * Just print out name so we can see which helpers are being called.
 */
void LaredoInstrumentVisitor::visitCallInst(CallInst &I){
    /*assert(I.getCalledFunction()->hasName());
    std::string fnName = I.getCalledFunction()->getName().str();
    printf("HELPER %s\n", fnName.c_str());
    fflush(stdout);*/
}



/*
 * Old LLVM code graveyard
 */

/* ValueMap code */

// get some register identifier so we can propagate taint between
// virtual registers from within functions
//ValueMap fMap;
//ValueMap::iterator FI = fMap.find(static_cast<Value*>(I.getOperand(0)));
//(*Out) << "op 0: " << *static_cast<Value*>(I.getOperand(0)) << "\n";
//(*Out) << "ID op 0: ";
//WriteAsOperand(*Out, static_cast<Value*>(I.getOperand(0)), true, 0);
//(*Out) << "\n";

// printf an instruction
//std::string line;
//raw_string_ostream line2(line);
//I.print(line2);
//printf("%s\n", line.c_str());

