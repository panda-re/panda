/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#include "llvm_taint_lib.h"
#include "guestarch.h"
#include "my_mem.h"

extern Shad *shadow;
extern int tainted_pointer ;

using namespace llvm;

/***
 *** PandaTaintFunctionPass
 ***/

char PandaTaintFunctionPass::ID = 0;
static RegisterPass<PandaTaintFunctionPass>
X("PandaTaint", "Analyze each instruction in a function for taint operations");

/*
 * Most of the time, existingTtbCache should be just passed as NULL so one is
 * created in the constructor.  Otherwise, pass in an existing one that was
 * created previously.
 */
FunctionPass *llvm::createPandaTaintFunctionPass(size_t tob_size,
        std::map<std::string, TaintTB*> *existingTtbCache) {
    return new PandaTaintFunctionPass(tob_size, existingTtbCache);
}

TaintOpBuffer* PandaTaintFunctionPass::getTaintOpBuffer(){
    return tbuf;
}

std::map<std::string, TaintTB*>* PandaTaintFunctionPass::getTaintTBCache(){
    return ttbCache;
}

bool PandaTaintFunctionPass::runOnFunction(Function &F){

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

        // create new ttb
        ttb = taint_tb_new(F.getName().str().c_str(),
            (int)F.getBasicBlockList().size());

        // clear global taint op buffer
        tob_clear(tbuf);

        // create slot tracker to keep track of LLVM values
        PTV->PST = createPandaSlotTracker(&F);
        PTV->PST->initialize();

        // process taint starting with the entry BB
        Function::iterator bb = F.begin();
        //printf("Processing entry BB...\n");
        PTV->visit(bb);
        assert(tbuf->size < tbuf_size); // make sure it didn't overflow

        // Copy the tbuf ops into the ttb
        ttb->entry->label = 0;
        ttb->entry->ops = tob_new(tbuf->size);
        tob_clear(ttb->entry->ops);
        memcpy(ttb->entry->ops->start, tbuf->start, tbuf->size);
        ttb->entry->ops->size = tbuf->size;


	if (qemu_loglevel_mask(CPU_LOG_TAINT_OPS)) {
	  qemu_log("OUT (TAINT OPS) (main) \n");
	  fprintf_tob(shadow, ttb->entry->ops, logfile);
	  qemu_log_flush();
	}


        // process other taint BBs if they exist
        int i = 0;
        if (ttb->numBBs > 1){
            bb++;
            for (Function::iterator bbe = F.end(); bb != bbe; bb++){

                // clear global taint op buffer
                tob_clear(tbuf);

                ttb->tbbs[i]->label = PTV->PST->getLocalSlot(bb);
                //printf("Processing BB %d...\n", LV->PST->getLocalSlot(bb));
                PTV->visit(bb);
                assert(tbuf->size < tbuf_size); // make sure it didn't overflow

                // Copy the tbuf ops into the ttb
                ttb->tbbs[i]->ops = tob_new(tbuf->size);
                tob_clear(ttb->tbbs[i]->ops);
                memcpy(ttb->tbbs[i]->ops->start, tbuf->start, tbuf->size);
                ttb->tbbs[i]->ops->size = tbuf->size;

		if (qemu_loglevel_mask(CPU_LOG_TAINT_OPS)) {
		  qemu_log("OUT (TAINT OPS) (other) %d\n", i);
		  fprintf_tob(shadow, ttb->tbbs[i]->ops, logfile);
		  qemu_log_flush();
		}



                i++;
            }
        }

        // delete slot tracker
        delete PTV->PST;

#ifndef TAINTSTATS
        // don't cache during statistics gathering because we need to keep
        // instruction count
        ttbCache->insert(std::pair<std::string, TaintTB*>(
            F.getName().str(), ttb));
#endif
    }

    //taint_tb_cleanup(ttb);
    //spit_mem_usage();

    return false; // no modifications made to function
}

void PandaTaintFunctionPass::debugTaintOps(){
    int j = 0;
    tob_rewind(ttb->entry->ops);
    while (!(tob_end(ttb->entry->ops))) {
        TaintOp *op;
        tob_op_read(ttb->entry->ops, &op);
        printf("op %d ", j);
        tob_op_print(NULL, op);
        j++;
    }

    // show taint ops for all BBs
    for (int i = 0; i < ttb->numBBs-1; i++){
        printf("\nBB %d:\n", ttb->tbbs[i]->label);

        j = 0;
        tob_rewind(ttb->tbbs[i]->ops);
        while (!(tob_end(ttb->tbbs[i]->ops))) {
	    TaintOp *op;
	    tob_op_read(ttb->tbbs[i]->ops, &op);
            printf("op %d ", j);
            tob_op_print(NULL, op);
            j++;
        }
    }
}

/*
 * This probably isn't the safest code.  Please don't fuzz the cache file ;)
 */
/*void PandaTaintFunctionPass::readTaintCache(){
    size_t cacheSize;
    char name[50];
    int numBBs;
    TaintTB *filettb;
    uint32_t taintbufsize;
    size_t n = 0;
    n = fread(&cacheSize, sizeof(size_t), 1, taintCache);
    assert(n);
    for (int i = 0; i < (int)cacheSize; i++){
        n = fread(name, 50, 1, taintCache);
        assert(n);
        n = fread(&numBBs, sizeof(int), 1, taintCache);
        assert(n);
        filettb = taint_tb_new(name, numBBs);
#ifdef TAINTDEBUG
        printf("reading %s from cache\n", name);
#endif
        n = fread(&filettb->entry->label, sizeof(((TaintBB*)0)->label), 1,
            taintCache);
        assert(n);
        n = fread(&taintbufsize, sizeof(uint32_t), 1, taintCache);
        assert(n);
        filettb->entry->ops = (TaintOpBuffer*)my_malloc(sizeof(TaintOpBuffer),
            poolid_taint_processor);
        filettb->entry->ops->size = taintbufsize;
        filettb->entry->ops->max_size = taintbufsize;
        filettb->entry->ops->start = (char*)my_malloc(taintbufsize,
            poolid_taint_processor);
        n = fread(filettb->entry->ops->start, taintbufsize, 1, taintCache);
        assert(n);

        // read additional BBs if they exist
        if (numBBs > 1){
            for (int j = 0; j < numBBs-1; j++){
                n = fread(&filettb->tbbs[j]->label,
                    sizeof(((TaintBB*)0)->label), 1, taintCache);
                assert(n);
                n = fread(&taintbufsize, sizeof(uint32_t), 1, taintCache);
                assert(n);
                filettb->tbbs[j]->ops = (TaintOpBuffer*)my_malloc(
                    sizeof(TaintOpBuffer), poolid_taint_processor);
                filettb->tbbs[j]->ops->size = taintbufsize;
                filettb->tbbs[j]->ops->max_size = taintbufsize;
                filettb->tbbs[j]->ops->start = (char*)my_malloc(taintbufsize,
                    poolid_taint_processor);
                n = fread(filettb->tbbs[j]->ops->start, taintbufsize, 1,
                    taintCache);
                assert(n);
            }
        }

        ttbCache->insert(std::pair<std::string, TaintTB*>(
            std::string(name), filettb));
    }
}

void PandaTaintFunctionPass::writeTaintCache(){
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
}*/

/***
 *** PandaSlotTracker
 ***/

PandaSlotTracker *llvm::createPandaSlotTracker(Function *F){
    return new PandaSlotTracker(F);
}

void PandaSlotTracker::initialize(){
    if (TheFunction && !FunctionProcessed){
        processFunction();
    }
}

void PandaSlotTracker::processFunction(){
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

void PandaSlotTracker::CreateFunctionSlot(const Value *V){
    assert(V->getType() != Type::getVoidTy(TheFunction->getContext()) &&
        !V->hasName() && "Doesn't need a slot!");
    unsigned DestSlot = fNext++;
    fMap[V] = DestSlot;
}

//void PandaSlotTracker::CreateMetadataSlot(const MDNode *N){
    // don't currently need this, but we will if we start using metadata
//}

int PandaSlotTracker::getLocalSlot(const Value *V){
    ValueMap::iterator FI = fMap.find(V);
    return FI == fMap.end() ? -1 : (int)FI->second;
}

/***
 *** PandaTaintVisitor
 ***/

PandaTaintVisitor::PandaTaintVisitor(PandaTaintFunctionPass *PTFunPass){
    PTFP = PTFunPass;
    tbuf = PTFP->getTaintOpBuffer();
    PST = NULL;
}

/*
 * Returns size in bytes of a generic LLVM value (could be operand or
 * instruction).
 */
int PandaTaintVisitor::getValueSize(Value *V){
    if (V->getType()->isIntegerTy()){
        return (int)ceil(V->getType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isPointerTy()){
        return (int)ceil(static_cast<SequentialType*>(V->getType())->
            getElementType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isFloatingPointTy()){
        return (int)ceil(V->getType()->getScalarSizeInBits() / 8.0);
    }
    else if (V->getType()->isStructTy()){
        StructType *S = cast<StructType>(V->getType());
        int size = 0;
        for (int i = 0, elements = S->getNumElements(); i < elements; i++) {
            //TODO: Handle the case where getElementType returns a derived type
            size += (int)ceil(S->getElementType(i)->getScalarSizeInBits() / 8.0);
        }
        return size;
    }
    else {
        // those are all that's supported for now
        //assert(1==0);
        printf("Error in getValueSize() for type %i\n", V->getType()->getTypeID());
        //    V->getParent()->getParent()->getName().str().c_str());
        return -1;
    }
}

// Delete taint at destination LLVM register
void PandaTaintVisitor::simpleDeleteTaintAtDest(int llvmReg){
    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = llvmReg;
    for (int i = 0; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }
}

// Copy taint from LLVM source to dest byte by byte
void PandaTaintVisitor::simpleTaintCopy(int source, int dest, int bytes){
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
        tob_op_write(tbuf, &op);
    }
}

// Compute operations, byte by byte
void PandaTaintVisitor::simpleTaintCompute(int source0, AddrType source0ty,
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
        tob_op_write(tbuf, &op);
    }
}

// Deals with taint ops for inttoptr and ptrtoint instructions
void PandaTaintVisitor::intPtrHelper(Instruction &I, int sourcesize, int destsize){

    // If the sizes are equal, then it is a series of simple copy operations
    if (sourcesize == destsize){
        simpleTaintCopy(PST->getLocalSlot(I.getOperand(0)),
            PST->getLocalSlot(&I), destsize);
    }

    // If the destination is smaller than the source, then copy the least
    // significant bytes, and delete taint at the most significant
    else if (sourcesize > destsize){
        simpleTaintCopy(PST->getLocalSlot(I.getOperand(0)),
            PST->getLocalSlot(&I), destsize);

        struct taint_op_struct op = {};
        struct addr_struct dst = {};
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = destsize; i < MAXREGSIZE; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // If the source is smaller than the destination, then copy the least
    // significant bytes, and delete taint at the bytes that are zero-extended
    else if (sourcesize < destsize){
        simpleTaintCopy(PST->getLocalSlot(I.getOperand(0)),
            PST->getLocalSlot(&I), sourcesize);

        // delete taint on extra bytes
        struct taint_op_struct op = {};
        struct addr_struct dst = {};
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = sourcesize; i < MAXREGSIZE; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }

    else {
        printf("Error: PtrToIntInst/IntToPtrInst size error\n");
        assert(1==0);
    }
}

// Deals with taint ops for integer add and subtract instructions
void PandaTaintVisitor::addSubHelper(Value *arg0, Value *arg1, Value *dstval){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = PST->getLocalSlot(arg0);
    int operand1 = PST->getLocalSlot(arg1);
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
        tob_op_write(tbuf, &op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);*/
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
        dst.val.la = PST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(ci-1, ai, ci)
        // compute(bi, ci, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = PST->getLocalSlot(dstval);
            src1.val.la = operand0;
            dst.val.la = PST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);

            src0.val.la = operand1;
            src1.val.la = PST->getLocalSlot(dstval);
            dst.val.la = PST->getLocalSlot(dstval);
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
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
        dst.val.la = PST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(ci-1, bi, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = PST->getLocalSlot(dstval);
            src1.val.la = operand1;
            src1.typ = LADDR;
            dst.val.la = PST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
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
        tob_op_write(tbuf, &op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);*/
        /**** TEST ****/

        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = CONST;
        src1.val.con = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(dstval);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(ci-1, ai, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = PST->getLocalSlot(dstval);
            src1.val.la = operand0;
            src1.typ = LADDR;
            dst.val.la = PST->getLocalSlot(dstval);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(arg0) && isa<Constant>(arg1)){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(dstval);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }

    else {
        assert(1==0);
    }
}

// Deals with taint ops for integer multiply instructions
void PandaTaintVisitor::mulHelper(BinaryOperator &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = PST->getLocalSlot(I.getOperand(0));
    int operand1 = PST->getLocalSlot(I.getOperand(1));
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
        tob_op_write(tbuf, &op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);*/
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
        }

        // compute(a0, c0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = PST->getLocalSlot(&I);
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(b0, c0, c0)
        src0.val.la = operand1;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);

        // compute(ci-1, ai, ci)
        // compute(bi, ci, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = PST->getLocalSlot(&I);
            src1.val.la = operand0;
            dst.val.la = PST->getLocalSlot(&I);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);

            src0.val.la = operand1;
            src1.val.la = PST->getLocalSlot(&I);
            dst.val.la = PST->getLocalSlot(&I);
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(ci-1, bi, ci)
        for (int i = 1; i < size; i++){
            src0.val.la = PST->getLocalSlot(&I);
            src1.val.la = operand1;
            src1.typ = LADDR;
            dst.val.la = PST->getLocalSlot(&I);
            dst.off = i;
            src0.off = i - 1;
            src1.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
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
        tob_op_write(tbuf, &op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);*/
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = PST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }

    else {
        assert(1==0);
    }
}

/*
 * XXX: Broken.  If you want a more accurate shift model, fix this.
 */
void PandaTaintVisitor::shiftHelper(BinaryOperator &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = PST->getLocalSlot(I.getOperand(0));
    int operand1 = PST->getLocalSlot(I.getOperand(1));
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = PST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
        }

        // copy each byte of operand 0 to each byte of destination through
        // compute ops
        src0.val.la = operand0;
        src1.val.la = PST->getLocalSlot(&I);
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
        }

        // propagate accumulated taint in c0 to all result bytes
        src0.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        src1.val.la = PST->getLocalSlot(&I);
        src1.off = 0;
        op.val.compute.b = src1;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 1; i < size; i++){
            dst.off = i;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // for now, copy taint to each destination byte through compute ops
    else if (isa<Constant>(I.getOperand(1))){
        src0.typ = LADDR;
        src0.val.la = operand0;
        src1.typ = LADDR;
        src1.val.la = operand0;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            src0.off = i;
            src1.off = i;
            dst.off = i;
            op.val.compute.a = src0;
            op.val.compute.b = src1;
            op.val.compute.c = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }

    else {
        assert(1==0);
    }
}

/*
 * Applies union of each byte of each operand to each byte of result
 */
void PandaTaintVisitor::approxArithHelper(Value *op0, Value *op1, Value *dest){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(op0->getType()->getScalarSizeInBits() / 8.0);
    int constantArgs = 0;

    // Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(dest) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    for (int oper = 0; oper < 2; oper++){
        // Operand is a constant, therefore it can't be tainted
        Value *curop = !oper ? op0 : op1;
        if (PST->getLocalSlot(curop) < 0){
            constantArgs++;

            // both args were constants, need to delete taint
            if (constantArgs == 2){
                op.typ = DELETEOP;
                dst.typ = LADDR;
                dst.val.la = PST->getLocalSlot(dest);
                for (int i = 0; i < size; i++){
                    dst.off = i;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, &op);
                }
                return;
            }

            continue;
        }

        // accumulate all of oper[i]'s taint into c0 of temp
        op.typ = COMPUTEOP;
        src0.typ = LADDR;
        src0.val.la = PST->getLocalSlot(curop);
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = PST->getLocalSlot(dest)+1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(dest) + 1;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;

        for (int i = 0; i < size; i++){
            src0.off = i;
            op.val.compute.a = src0;
            tob_op_write(tbuf, &op);
        }
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(dest) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(dest) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(dest);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

// Currently only used for and, or, and xor
void PandaTaintVisitor::simpleArithHelper(BinaryOperator &I){
    int source0 = PST->getLocalSlot(I.getOperand(0));
    AddrType source0ty = isa<Constant>(I.getOperand(0)) ? CONST : LADDR;
    int source1 = PST->getLocalSlot(I.getOperand(1));
    AddrType source1ty = isa<Constant>(I.getOperand(1)) ? CONST : LADDR;
    int dest = PST->getLocalSlot(&I);
    int bytes = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    simpleTaintCompute(source0, source0ty, source1, source1ty, dest, bytes);
}

// Terminator instructions
void PandaTaintVisitor::visitReturnInst(ReturnInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};

    // need to copy taint to return register if it returns a value
    int result = PST->getLocalSlot(I.getReturnValue());
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
            tob_op_write(tbuf, &op);
        }
    }

    op.typ = RETOP;
    tob_op_write(tbuf, &op);
}

void PandaTaintVisitor::visitBranchInst(BranchInst &I){
    // write instruction boundary op
    struct taint_op_struct op = {};
    op.typ = INSNSTARTOP;
    char name[11] = "condbranch";
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = 0;
    op.val.insn_start.flag = INSNREADLOG;
    op.val.insn_start.cur_branch_bb = PST->getLocalSlot(I.getParent());
    op.val.insn_start.branch_cond_llvm_reg =
        I.isConditional() ? PST->getLocalSlot(I.getCondition()) : -1;
    for (int i = 0; i < (int)I.getNumSuccessors(); i++){
        op.val.insn_start.branch_labels[i] =
            PST->getLocalSlot(I.getSuccessor(i));
    }
    tob_op_write(tbuf, &op);
}

void PandaTaintVisitor::visitSwitchInst(SwitchInst &I){
    // write instruction boundary op
    struct taint_op_struct op = {};
    op.typ = INSNSTARTOP;
    char name[7] = "switch";
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = 0;
    op.val.insn_start.flag = INSNREADLOG;
    op.val.insn_start.cur_branch_bb = PST->getLocalSlot(I.getParent());
    unsigned successors = I.getNumSuccessors();
    int len = successors + 1;

    op.val.insn_start.switch_len = len;
    op.val.insn_start.switch_conds = (int64_t*)my_malloc(len * sizeof(int64_t), poolid_taint_processor);
    op.val.insn_start.switch_labels = (int*)my_malloc(len * sizeof(int), poolid_taint_processor);

    // Other cases
    int i = 0;
    for (llvm::SwitchInst::CaseIt it = I.case_begin(); it != I.case_end(); i++, it++){
        op.val.insn_start.switch_conds[i] =
            it.getCaseValue()->getSExtValue();
        op.val.insn_start.switch_labels[i] =
            PST->getLocalSlot(it.getCaseSuccessor());
    }

    // Put default case at end of array
    op.val.insn_start.switch_conds[len-1] = 0xDEADBEEF;
    op.val.insn_start.switch_labels[len-1] =
        PST->getLocalSlot(I.getDefaultDest());

    tob_op_write(tbuf, &op);
}

void PandaTaintVisitor::visitIndirectBrInst(IndirectBrInst &I){}
void PandaTaintVisitor::visitInvokeInst(InvokeInst &I){}
void PandaTaintVisitor::visitResumeInst(ResumeInst &I){}

/*
 * Treat unreachable the same way as return.  This matters, for example, when
 * there is a call to cpu_loop_exit() in a helper function, followed by an
 * unreachable instruction.  Functions that end with unreachable return void, so
 * we don't have to worry about taint transfer, we just have to tell the taint
 * processor we are returning.
 */
void PandaTaintVisitor::visitUnreachableInst(UnreachableInst &I){
    struct taint_op_struct op = {};
    op.typ = RETOP;
    tob_op_write(tbuf, &op);
}

// Binary operators
void PandaTaintVisitor::visitBinaryOperator(BinaryOperator &I){
    switch (I.getOpcode()){

        case Instruction::Add:
            addSubHelper(I.getOperand(0), I.getOperand(1), &I);
            //simpleArithHelper(I);
            break;

        case Instruction::FAdd:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::Sub:
            addSubHelper(I.getOperand(0), I.getOperand(1), &I);
            //simpleArithHelper(I);
            break;

        case Instruction::FSub:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::Mul:
            //mulHelper(I);
            //simpleArithHelper(I);
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::FMul:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::UDiv:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::SDiv:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::FDiv:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::URem:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::SRem:
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
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
            if (0 /*(!isa<Constant>(I.getOperand(0)))
                && (isa<Constant>(I.getOperand(1)))
                && (getValueSize(&I) == 8)*/){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                if (con == 56){
                    //printf("hacked shl\n");
                    int srcval = PST->getLocalSlot(I.getOperand(0));
                    int dstval = PST->getLocalSlot(&I);
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
                    tob_op_write(tbuf, &op);

                    op.typ = DELETEOP;
                    for (int i = 0; i < 7; i++){
                        dst.off = i;
                        op.val.deletel.a = dst;
                        tob_op_write(tbuf, &op);
                    }
                }
                else {
                    approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
                }
            }
            else {
                approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            }
            break;

        case Instruction::LShr:
            //shiftHelper(I);
            //simpleArithHelper(I);

            /*
             * FIXME: Hack to account for some constant operands.  Make this
             * more generic when we have more time.
             */
            if (0 /*(!isa<Constant>(I.getOperand(0)))
                && (isa<Constant>(I.getOperand(1)))
                && (getValueSize(&I) == 8)*/){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                if ((con > 0) && (con <= 8)){
                    //printf("hacked lshr\n");
                    int srcval = PST->getLocalSlot(I.getOperand(0));
                    int dstval = PST->getLocalSlot(&I);
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
                        tob_op_write(tbuf, &op);
                    }

                    op.typ = DELETEOP;
                    dst.off = 7;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, &op);
                }
                else if ((con >= 56) && (con < 64)){
                    //printf("hacked lshr\n");
                    int srcval = PST->getLocalSlot(I.getOperand(0));
                    int dstval = PST->getLocalSlot(&I);
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
                    tob_op_write(tbuf, &op);

                    op.typ = DELETEOP;
                    for (int i = 1; i < 8; i++){
                        dst.off = i;
                        op.val.deletel.a = dst;
                        tob_op_write(tbuf, &op);
                    }
                }
                else {
                    approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
                }
            }
            else {
                approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            }
            break;

        case Instruction::AShr:
            //shiftHelper(I);
            //simpleArithHelper(I);
            approxArithHelper(I.getOperand(0), I.getOperand(1), &I);
            break;

        case Instruction::And:
            // TODO: think about more precise propagation when we have constants
            // on hand.  this goes for shift also.
            if (0 /*isa<Constant>(I.getOperand(1))*/){
                uint64_t con = static_cast<ConstantInt*>
                    (I.getOperand(1))->getZExtValue();
                int srcval = PST->getLocalSlot(I.getOperand(0));
                int dstval = PST->getLocalSlot(&I);
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
                        tob_op_write(tbuf, &op);
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
void PandaTaintVisitor::visitAllocaInst(AllocaInst &I){
    simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
}

void PandaTaintVisitor::loadHelper(Value *srcval, Value *dstval, int len, int is_mmu){
    // local is LLVM register destination of load
    int local = PST->getLocalSlot(dstval);

    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[5] = "load";

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = len;  
    if (is_mmu) {
      // NB: we need one ld callback per copy
      op.val.insn_start.num_ops += len;  
    }
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, &op);

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
        tob_op_write(tbuf, &op);
    }

    // taint ops for ld callbacks
    if (is_mmu) {
        op.typ = LDCALLBACKOP;    
        for (int i = 0; i < len; i++){   
            src.off = i;
            op.val.ldcallback.a = src;
	    tob_op_write(tbuf, &op);
	}
    }

    if (tainted_pointer) {

    struct addr_struct src0 = {};
    struct addr_struct src1 = {};

    // Pointer is a constant, therefore it can't be tainted
    if (PST->getLocalSlot(srcval) < 0){
        //printf("CONSTANT\n");
        return;
    }

    // accumulate all of b's taint into one byte of temp register
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(srcval);
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = PST->getLocalSlot(srcval);
    src1.off = 0;
    dst.typ = RET;
    dst.off = 0;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;
    tob_op_write(tbuf, &op);

    src1.typ = RET;
    op.val.compute.b = src1;
    for (int i = 1; i < len; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);
    }

    // propagate accumulated taint in temp[0] to all result bytes
    src0.typ = RET;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(dstval);
    src1.typ = LADDR;
    dst.val.la = PST->getLocalSlot(dstval);
    dst.typ = LADDR;
    for (int i = 0; i < len; i++){
        src1.off = i;
        dst.off = i;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
    } // tainted_pointer on

}

void PandaTaintVisitor::visitLoadInst(LoadInst &I){
    /*
     * For source code analysis, loading a global value is likely the root
     * pointer of CPUState or a pointer for something inside of it, therefore it
     * isn't tainted.
     */
    // XXX: We are commenting this out now since global values may be referenced
    // in helper functions
    /*if (isa<GlobalValue>(I.getPointerOperand())){
        simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
        return;
    }*/

    // get source operand length
    int len = ceil(static_cast<SequentialType*>(I.getOperand(0)->
        getType())->getElementType()->getScalarSizeInBits() / 8.0);
    loadHelper(I.getOperand(0), &I, len, 0);
}

void PandaTaintVisitor::storeHelper(Value *srcval, Value *dstval, int len, int is_mmu){
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
    tob_op_write(tbuf, &op);

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    if (!tainted_pointer) {
        op.val.insn_start.num_ops = len;
    }
    else {
        // tainted pointer mode is on
        // if pointer is a constant, it can't be tainted so we don't include taint
        // ops to propagate tainted pointer
        if (PST->getLocalSlot(dstval) < 0){
            op.val.insn_start.num_ops = len;
	}
	else  {
            // need INSNSTART to fill in tainted pointer ops too
            op.val.insn_start.num_ops = len * 3;
	}
    } // !tainted_pointer

    if (is_mmu) {
      // NB: len more ops for ld callbacks
      op.val.insn_start.num_ops += len;
    }
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, &op);

    if (srcConstant){
        op.typ = DELETEOP;
        dst.typ = UNK;
        dst.val.ua = 0;
        dst.flag = READLOG;
        for (int i = 0; i < len; i++){
            dst.off = i;
            op.val.deletel.a = dst;
	    tob_op_write(tbuf, &op);
        }
    }
    else {
        op.typ = COPYOP;
        dst.typ = UNK;
        dst.flag = READLOG;
        dst.val.ua = 0;
        src.typ = LADDR;
        src.val.la = PST->getLocalSlot(srcval);
        for (int i = 0; i < len; i++){
            src.off = i;
            dst.off = i;
            op.val.copy.a = src;
            op.val.copy.b = dst;
            tob_op_write(tbuf, &op);
        }
    }

    // taint ops for st callbacks
    if (is_mmu) {
        op.typ = STCALLBACKOP;	
        for (int i = 0; i < len; i++){
  	    dst.off = i;
	    op.val.stcallback.a = dst;
	    tob_op_write(tbuf, &op);
	}
    }


    if (tainted_pointer) {

    struct addr_struct src0 = {};
    struct addr_struct src1 = {};

    // Pointer is a constant, therefore it can't be tainted
    if (PST->getLocalSlot(dstval) < 0){
        return;
    }

    // accumulate all of b's taint into temp[0]
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(dstval);
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
        tob_op_write(tbuf, &op);
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
        tob_op_write(tbuf, &op);
    }
    }
}

/*
 * We should only care about non-volatile stores, the volatile stores are
 * irrelevant to guest execution.  Volatile stores come in pairs for each guest
 * instruction, so we can gather statistics looking at every other volatile
 * store.
 */
bool evenStore = false;
void PandaTaintVisitor::visitStoreInst(StoreInst &I){


  // look for magic taint pc update info
  MDNode *md = I.getMetadata("pcupdate.md");
  if (md != NULL) {
    // found store instruction that contains PC.  
    // translate that into a taint processor instruction
    // so that taint processor can know the pc too
    Value *srcval = I.getOperand(0);
    assert (isa<Constant>(srcval));
    uint64_t pc = * ((cast<ConstantInt>(srcval))->getValue().getRawData());
    //    printf ("pc=0x%lx\n", pc);
    TaintOp op;
    op.typ = PCOP;
    op.val.pc = pc;
    tob_op_write(tbuf, &op);
  }

  
  


    if (I.isVolatile()){
#ifdef TAINTSTATS
        evenStore = !evenStore;
        if (evenStore){
            assert(shadow);
            dump_taint_stats(shadow);
        }
#endif
        return;
    }

    // get source operand length
    int len = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);
    storeHelper(I.getOperand(0), I.getOperand(1), len, 0);
}

void PandaTaintVisitor::visitFenceInst(FenceInst &I){}
void PandaTaintVisitor::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I){}
void PandaTaintVisitor::visitAtomicRMWInst(AtomicRMWInst &I){}

/*
 * In TCG->LLVM translation, it seems like this instruction is only used to get
 * the pointer to the CPU state.  Because of this, we will just delete taint at
 * the destination LLVM register.
 */
void PandaTaintVisitor::visitGetElementPtrInst(GetElementPtrInst &I){
    simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
}

// Cast operators

void PandaTaintVisitor::visitTruncInst(TruncInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: trunc constant operand (FIXME)\n");
        assert(1==0);
        return;
    }

    int destsize = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    int srcval = PST->getLocalSlot(I.getOperand(0));
    int dstval = PST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, destsize);

    // delete taint on extra bytes
    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = destsize; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitZExtInst(ZExtInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: zext constant operand (FIXME)\n");
        assert(1==0);
        return;
    }

    int sourcesize = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() /
        8.0);
    int srcval = PST->getLocalSlot(I.getOperand(0));
    int dstval = PST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, sourcesize);

    struct taint_op_struct op = {};
    struct addr_struct dst = {};
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = sourcesize; i < MAXREGSIZE; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitSExtInst(SExtInst &I){
    if (isa<Constant>(I.getOperand(0))){
        // Haven't seen this yet, assuming it won't happen
        printf("Error: sext constant operand (FIXME)\n");
        assert(1==0);
        return;
    }
    int sourcesize = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() /
        8.0);
    int destsize = ceil(I.getType()->getScalarSizeInBits() / 8.0);
    int srcval = PST->getLocalSlot(I.getOperand(0));
    int dstval = PST->getLocalSlot(&I);
    simpleTaintCopy(srcval, dstval, sourcesize);

    // apply compute taint to sign-extended bytes
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    src0.typ = src1.typ = dst.typ = LADDR;
    src0.val.la = src1.val.la = PST->getLocalSlot(I.getOperand(0));
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = sourcesize; i < destsize; i++){
        src0.off = sourcesize - 1;
        src1.off = sourcesize - 1;
        dst.off = i;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitFPToUIInst(FPToUIInst &I){
    //Assume that the cast will be to the same size destination
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    //Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    if (PST->getLocalSlot(I.getOperand(0)) < 0) {
      // arg was constant, need to delete taint
      op.typ = DELETEOP;
      dst.typ = LADDR;
      dst.val.la = PST->getLocalSlot(&I);
      for (int i = 0; i < size; i++) {
          dst.off = i;
          op.val.deletel.a = dst;
          tob_op_write(tbuf, &op);
      }
      return;
    }

    // accumulate all of oper[1]'s taint into c0 of temp
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(I.getOperand(0));
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;

    for (int i = 0; i < size; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(&I);

    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitFPToSIInst(FPToSIInst &I){
    //Assume that the cast will be to the same size destination
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    //Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    if (PST->getLocalSlot(I.getOperand(0)) < 0) {
      // arg was constant, need to delete taint
      op.typ = DELETEOP;
      dst.typ = LADDR;
      dst.val.la = PST->getLocalSlot(&I);
      for (int i = 0; i < size; i++) {
          dst.off = i;
          op.val.deletel.a = dst;
          tob_op_write(tbuf, &op);
      }
      return;
    }

    // accumulate all of oper[1]'s taint into c0 of temp
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(I.getOperand(0));
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;

    for (int i = 0; i < size; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(&I);

    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitUIToFPInst(UIToFPInst &I){}
void PandaTaintVisitor::visitSIToFPInst(SIToFPInst &I){}
void PandaTaintVisitor::visitFPTruncInst(FPTruncInst &I){}
void PandaTaintVisitor::visitFPExtInst(FPExtInst &I){}

void PandaTaintVisitor::visitPtrToIntInst(PtrToIntInst &I){
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

void PandaTaintVisitor::visitIntToPtrInst(IntToPtrInst &I){
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
void PandaTaintVisitor::visitBitCastInst(BitCastInst &I){
    simpleDeleteTaintAtDest(PST->getLocalSlot(&I));
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
void PandaTaintVisitor::visitICmpInst(ICmpInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int operand0 = PST->getLocalSlot(I.getOperand(0));
    int operand1 = PST->getLocalSlot(I.getOperand(1));
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(c0, ai, c0)
        // compute(c0, bi, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src1.off = i;
            src1.val.la = operand0;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
            src1.val.la = operand1;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
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
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(c0, bi, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src1.off = i;
            op.val.compute.b = src1;
            tob_op_write(tbuf, &op);
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
        tob_op_write(tbuf, &op2);
        a.off = 1;
        op2.val.label.l = 1;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 2;
        op2.val.label.l = 2;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);
        a.off = 3;
        op2.val.label.l = 3;
        op2.val.label.a = a;
        tob_op_write(tbuf, &op2);*/
        /**** TEST ****/

        // compute(a0, b0, c0)
        src0.typ = LADDR;
        src0.val.la = operand0;
        src0.off = 0;
        src1.typ = CONST;
        src1.val.con = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(&I);
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);

        // compute(c0, ai, c0)
        op.val.compute.a = dst;
        for (int i = 1; i < size; i++){
            src0.off = i;
            op.val.compute.b = src0;
            tob_op_write(tbuf, &op);
        }
    }

    // constant operands contain no taint
    else if (isa<Constant>(I.getOperand(0)) && isa<Constant>(I.getOperand(1))){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(&I);
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }

    else {
        assert(1==0);
    }
}

void PandaTaintVisitor::visitFCmpInst(FCmpInst &I){
    //This instruction can be modeled as a simple floating point subtraction
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
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    for (int oper = 0; oper < 2; oper++){
        // Operand is a constant, therefore it can't be tainted
        if (PST->getLocalSlot(I.getOperand(oper)) < 0){
            constantArgs++;

            // both args were constants, need to delete taint
            if (constantArgs == 2){
                op.typ = DELETEOP;
                dst.typ = LADDR;
                dst.val.la = PST->getLocalSlot(&I);
                for (int i = 0; i < size; i++){
                    dst.off = i;
                    op.val.deletel.a = dst;
                    tob_op_write(tbuf, &op);
                }
                return;
            }

            continue;
        }

        // accumulate all of oper[i]'s taint into c0 of temp
        op.typ = COMPUTEOP;
        src0.typ = LADDR;
        src0.val.la = PST->getLocalSlot(I.getOperand(oper));
        src0.off = 0;
        src1.typ = LADDR;
        src1.val.la = PST->getLocalSlot(&I)+1;
        src1.off = 0;
        dst.typ = LADDR;
        dst.off = 0;
        dst.val.la = PST->getLocalSlot(&I) + 1;
        op.val.compute.a = src0;
        op.val.compute.b = src1;
        op.val.compute.c = dst;

        for (int i = 0; i < size; i++){
            src0.off = i;
            op.val.compute.a = src0;
            tob_op_write(tbuf, &op);
        }
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitPHINode(PHINode &I){
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};
    int size = getValueSize(&I);

    //Delete taint at destination
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }

    char name[4] = "phi";
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = size;

    unsigned len = I.getNumIncomingValues();
    op.val.insn_start.phi_len = len;
    op.val.insn_start.phi_vals = (int*)my_malloc(len * sizeof(int), poolid_taint_processor);
    op.val.insn_start.phi_labels = (int*)my_malloc(len * sizeof(int), poolid_taint_processor);

    for (unsigned i = 0; i < len; i++){
        op.val.insn_start.phi_vals[i] = PST->getLocalSlot(I.getIncomingValue(i));
        op.val.insn_start.phi_labels[i] = PST->getLocalSlot(I.getIncomingBlock(i));
    }

    tob_op_write(tbuf, &op);

    op.typ = COPYOP;
    dst.typ = LADDR;
    dst.val.la = PST->getLocalSlot(&I);
    src.typ = UNK;
    src.val.ua = 0;

    for (int i = 0; i < size; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }
}

/*
 * Taint model for LLVM bswap intrinsic.
 */
void PandaTaintVisitor::bswapHelper(CallInst &I){
    int bytes = getValueSize(&I);
    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    dst.val.la = PST->getLocalSlot(&I);
    src.typ = LADDR;
    src.val.la = PST->getLocalSlot(I.getArgOperand(0));

    for (int i = 0; i < bytes; i++){
        src.off = i;
        dst.off = bytes-i-1;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }
}

/*
 * Taint model for LLVM memcpy intrinsic.
 */
void PandaTaintVisitor::memcpyHelper(CallInst &I){
    int bytes = 0;
    Value *bytes_ir  = const_cast<Value*>(I.getArgOperand(2));
    if (ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir)) {
        if (CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }
    }

    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};

    char name[7] = "memcpy";
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = bytes;
    op.val.insn_start.flag = INSNREADLOG;

    tob_op_write(tbuf, &op);

    op.typ = COPYOP;
    dst.typ = UNK;
    dst.val.ua = 0;
    dst.flag = READLOG;
    src.typ = UNK;
    src.val.ua = 0;
    src.flag = READLOG;

    for (int i = 0; i < bytes; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }
}

/*
 * Taint model for LLVM memset intrinsic.
 */
void PandaTaintVisitor::memsetHelper(CallInst &I){
    int bytes = 0;
    Value *bytes_ir  = const_cast<Value*>(I.getArgOperand(2));
    if (ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir)) {
        if (CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }
    }

    if (bytes > 100) {
      //This happens mostly in cpu state reset
      printf("Note: taint ignoring memset greater than 100 bytes\n");
      return;
    }

    struct taint_op_struct op = {};
    struct addr_struct dst = {};

    //Second operand is a constant
    assert(PST->getLocalSlot(I.getArgOperand(1)) < 0);

    char name[7] = "memset";
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = bytes;
    op.val.insn_start.flag = INSNREADLOG;

    tob_op_write(tbuf, &op);

    op.typ = DELETEOP;
    dst.typ = UNK;
    dst.val.ua = 0;
    dst.flag = READLOG;
    for (int i = 0; i < bytes; i++){
        dst.off = i;
        op.val.deletel.a = dst;
        tob_op_write(tbuf, &op);
    }
}

/*
 * Taint model for LLVM ctlz intrinsic.
 */
void PandaTaintVisitor::ctlzHelper(CallInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    // Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    // Operand is a constant, therefore it can't be tainted
    if (PST->getLocalSlot(I.getArgOperand(0)) < 0){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
        return;
    }

    // accumulate all of oper[i]'s taint into c0 of temp
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(I.getArgOperand(0));
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = PST->getLocalSlot(&I)+1;
    src1.off = 0;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;

    for (int i = 0; i < size; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

/*
 * Taint model for floating point math functions like sin(), cos(), etc.  Very
 * similar to approxArithHelper(), except it takes only one operand.
 */
void PandaTaintVisitor::floatHelper(CallInst &I){
    struct taint_op_struct op = {};
    struct addr_struct src0 = {};
    struct addr_struct src1 = {};
    struct addr_struct dst = {};
    op.typ = COMPUTEOP;
    int size = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);

    // Delete taint in accumulator (next register which hasn't been used yet)
    op.typ = DELETEOP;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.deletel.a = dst;
    tob_op_write(tbuf, &op);

    // Operand is a constant, therefore it can't be tainted
    if (PST->getLocalSlot(I.getArgOperand(0)) < 0){
        op.typ = DELETEOP;
        dst.typ = LADDR;
        dst.val.la = PST->getLocalSlot(&I);
        for (int i = 0; i < size; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
        return;
    }

    // accumulate all of oper[i]'s taint into c0 of temp
    op.typ = COMPUTEOP;
    src0.typ = LADDR;
    src0.val.la = PST->getLocalSlot(I.getArgOperand(0));
    src0.off = 0;
    src1.typ = LADDR;
    src1.val.la = PST->getLocalSlot(&I)+1;
    src1.off = 0;
    dst.typ = LADDR;
    dst.off = 0;
    dst.val.la = PST->getLocalSlot(&I) + 1;
    op.val.compute.a = src0;
    op.val.compute.b = src1;
    op.val.compute.c = dst;

    for (int i = 0; i < size; i++){
        src0.off = i;
        op.val.compute.a = src0;
        tob_op_write(tbuf, &op);
    }

    // propagate accumulated taint in c0 to all result bytes
    src0.val.la = PST->getLocalSlot(&I) + 1;
    src0.off = 0;
    op.val.compute.a = src0;
    src1.val.la = PST->getLocalSlot(&I) + 1;
    src1.off = 0;
    op.val.compute.b = src1;
    dst.val.la = PST->getLocalSlot(&I);
    for (int i = 0; i < size; i++){
        dst.off = i;
        op.val.compute.c = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitCallInst(CallInst &I){
    Function *called = I.getCalledFunction();
    if (!called) {
        //assert(1==0);
        //return; // doesn't have name, we can't process it
        // Might be ok for now, but we might need to revisit.
        printf("Note: skipping taint analysis of statically unknowable call in %s.\n",
            I.getParent()->getParent()->getName().str().c_str());
        return;
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
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::memcpy){
         memcpyHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::memset){
         memsetHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID() == Intrinsic::ctlz){
         ctlzHelper(I);
         return;
    }
    else if (I.getCalledFunction()->getIntrinsicID()
            != Intrinsic::not_intrinsic){
        printf("Note: unsupported intrinsic %s in %s.\n",
            I.getCalledFunction()->getName().str().c_str(),
            I.getParent()->getParent()->getName().str().c_str());
        //assert(1==0);
    }
    else if (!calledName.compare("__ldb_mmu_panda")
            || !calledName.compare("__ldw_mmu_panda")
            || !calledName.compare("__ldl_mmu_panda")
            || !calledName.compare("__ldq_mmu_panda")){

        // guest load in whole-system mode
        int len = getValueSize(&I);
        loadHelper(I.getArgOperand(0), &I, len, 1);
        return;
    }
    else if (!calledName.compare("__stb_mmu_panda")
            || !calledName.compare("__stw_mmu_panda")
            || !calledName.compare("__stl_mmu_panda")
            || !calledName.compare("__stq_mmu_panda")){

        // guest store in whole-system mode
        int len = getValueSize(I.getArgOperand(1));

	/*
	printf ("calling storeHelper.  mmu = 1.\n");

	// printf an instruction
	std::string line;   
	raw_string_ostream line2(line);
	I.print(line2); 
	printf("%s\n", line.c_str());  
                                                                                                                
	printf ("arg1\n");
	I.getArgOperand(1)->dump();
	printf ("\n");
	printf ("arg0\n");
	I.getArgOperand(0)->dump();
	printf ("\n");
	*/

	

	//	printf ("arg1 = [%s]\n", ((I.getArgOperand(1))));
	storeHelper(/*src=*/ I.getArgOperand(1), /*dest=*/I.getArgOperand(0), len, 1);
        return;
    }
    else if (!calledName.compare("sin")
            || !calledName.compare("cos")
            || !calledName.compare("tan")
            || !calledName.compare("log")
            || !calledName.compare("__isinf")
            || !calledName.compare("__isnan")
            || !calledName.compare("rint")
            || !calledName.compare("floor")
            || !calledName.compare("abs")
            || !calledName.compare("ceil")
            || !calledName.compare("exp2")){

        floatHelper(I);
        return;
    }
    else if (!calledName.compare("ldexp")
            || !calledName.compare("atan2")){

        approxArithHelper(I.getArgOperand(0), I.getArgOperand(1), &I);
        return;
    }
    else if (!calledName.compare(0, 9, "helper_in") && calledName.size() == 10){
        /*
         * The last character of the instruction name determines the size of data transfer
         * b = single byte
         * w = 2 bytes
         * l - 4 bytes
         */
        char type = *calledName.rbegin();
        int len;
        if (type == 'b') {
            len = 1;
        } else if (type == 'w') {
            len = 2;
        } else {
            len = 4;
        }

        /* helper_in instructions will be modeled as loads with various lengths */
        portLoadHelper(I.getArgOperand(0), &I, len);
        return;
    }
    else if (!calledName.compare(0, 10, "helper_out") && calledName.size() == 11){
        /*
         * The last character of the instruction name determines the size of data transfer
         * b = single byte
         * w = 2 bytes
         * l - 4 bytes
         */
        char type = *calledName.rbegin();
        int len;
        if (type == 'b') {
            len = 1;
        } else if (type == 'w') {
            len = 2;
        } else {
            len = 4;
        }

        /* helper_out instructions will be modeled as stores with various lengths */
        portStoreHelper(I.getArgOperand(1), I.getArgOperand(0), len);
        return;
    }

    std::map<std::string, TaintTB*> *ttbCache = PTFP->getTaintTBCache();
    std::map<std::string, TaintTB*>::iterator it = ttbCache->find(calledName);

    /*
     * If it's not currently in the cache and it's something that should be in
     * the cache (per the if statement), then we need to create a new function
     * pass and put it in the cache.
     */
    if (it == ttbCache->end() && I.getCalledFunction()
        && !I.getCalledFunction()->isDeclaration()
        && !I.getCalledFunction()->isIntrinsic()){

        FunctionPass *newPTFP =
            createPandaTaintFunctionPass(10*1048576, ttbCache);

        newPTFP->runOnFunction(*I.getCalledFunction());
        it = ttbCache->find(calledName);
        delete newPTFP;
        assert(it != ttbCache->end());
    }

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
                    tob_op_write(tbuf, &op);
                }
            }
            else {
                op.typ = COPYOP;
                src.val.la = PST->getLocalSlot(arg);
                dst.val.la = i;
                for (int j = 0; j < argBytes; j++){
                    src.off = j;
                    dst.off = j;
                    op.val.copy.a = src;
                    op.val.copy.b = dst;
                    tob_op_write(tbuf, &op);
                }
            }
        }

        // call op (function name, pointer to taint buf, increment frame level)
        op.typ = CALLOP;
        strncpy(op.val.call.name, it->first.c_str(), FUNCNAMELENGTH);
        op.val.call.ttb = it->second;
        tob_op_write(tbuf, &op);

        // copy return reg to value in this frame, if applicable
        int slot = PST->getLocalSlot(&I);
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
                tob_op_write(tbuf, &op);
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

// this is essentially a copy of loadHelper without the tainted pointer code
void PandaTaintVisitor::portLoadHelper(Value *srcval, Value *dstval, int len){
    // local is LLVM register destination of load
    int local = PST->getLocalSlot(dstval);

    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[5] = "load";

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = len;
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, &op);

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
        tob_op_write(tbuf, &op);
    }
}

// this is essentially a copy of storeHelper without the tainted pointer code
void PandaTaintVisitor::portStoreHelper(Value *srcval, Value *dstval, int len){
    // can't propagate taint from a constant
    bool srcConstant = isa<Constant>(srcval);

    struct addr_struct src = {};
    struct addr_struct dst = {};
    struct taint_op_struct op = {};
    char name[6] = "store";

    // write instruction boundary op
    op.typ = INSNSTARTOP;
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    op.val.insn_start.num_ops = len;
    op.val.insn_start.flag = INSNREADLOG;
    tob_op_write(tbuf, &op);

    if (srcConstant){
        op.typ = DELETEOP;
        dst.typ = UNK;
        dst.val.ua = 0;
        dst.flag = READLOG;
        for (int i = 0; i < len; i++){
            dst.off = i;
            op.val.deletel.a = dst;
            tob_op_write(tbuf, &op);
        }
    }
    else {
        op.typ = COPYOP;
        dst.typ = UNK;
        dst.flag = READLOG;
        dst.val.ua = 0;
        src.typ = LADDR;
        src.val.la = PST->getLocalSlot(srcval);
        for (int i = 0; i < len; i++){
            src.off = i;
            dst.off = i;
            op.val.copy.a = src;
            op.val.copy.b = dst;
            tob_op_write(tbuf, &op);
        }
    }
}

/*
 * This may need to become more complex for more complex cases of this
 * instruction. Currently we are just treating it like a branch, but with values
 * filled in instead of branch targets.
 */
void PandaTaintVisitor::visitSelectInst(SelectInst &I){
    // write instruction boundary op
    struct taint_op_struct op = {};
    op.typ = INSNSTARTOP;
    char name[7] = "select";
    strncpy(op.val.insn_start.name, name, OPNAMELENGTH);
    int srcbytelen = getValueSize(&I);
    op.val.insn_start.num_ops = srcbytelen;
    op.val.insn_start.flag = INSNREADLOG;
    op.val.insn_start.branch_labels[0] = PST->getLocalSlot(I.getTrueValue());
    op.val.insn_start.branch_labels[1] = PST->getLocalSlot(I.getFalseValue());
    tob_op_write(tbuf, &op);

    // write taint ops
    memset(&op, 0, sizeof(op));
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    src.typ = UNK;
    src.val.ua = 0;
    src.flag = READLOG;
    dst.val.la = PST->getLocalSlot(&I);

    for (int i = 0; i < srcbytelen; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitVAArgInst(VAArgInst &I){}
void PandaTaintVisitor::visitExtractElementInst(ExtractElementInst &I){}
void PandaTaintVisitor::visitInsertElementInst(InsertElementInst &I){}
void PandaTaintVisitor::visitShuffleVectorInst(ShuffleVectorInst &I){}

/*
 * This may need to become more complex for more complex cases of this
 * instruction.
 */
void PandaTaintVisitor::visitExtractValueInst(ExtractValueInst &I){
    int src = PST->getLocalSlot(I.getAggregateOperand());
    int dst = PST->getLocalSlot(&I);
    int bytes = getValueSize(&I);
    simpleTaintCopy(src, dst, bytes);
}

void PandaTaintVisitor::visitInsertValueInst(InsertValueInst &I){
    int op0 = PST->getLocalSlot(I.getOperand(0));
    int op1 = PST->getLocalSlot(I.getOperand(1));
    int idx = 0;
    if (I.getNumOperands() > 2) {
        llvm::ConstantInt* idx_ir = dyn_cast<llvm::ConstantInt>(I.getOperand(2));
        idx = idx_ir->getSExtValue();
    }
    int rst = PST->getLocalSlot(&I);
    int bytes0 = ceil(I.getOperand(0)->getType()->getScalarSizeInBits() / 8.0);
    int bytes1 = ceil(I.getOperand(1)->getType()->getScalarSizeInBits() / 8.0);

    //Only support 2 or 3 operands
    assert(I.getNumOperands() == 2 || I.getNumOperands() == 3);
    //Only support 64 bit + 64 bit and 64 bit + 16 bit
    assert((bytes0 == 8 || bytes0 == 0) && (bytes1 == 8 || bytes1 == 2));

    struct taint_op_struct op = {};
    struct addr_struct src = {};
    struct addr_struct dst = {};
    op.typ = COPYOP;
    dst.typ = LADDR;
    dst.val.la = rst;
    src.typ = LADDR;
    src.val.la = op0;

    for (int i = 0; i < bytes0; i++){
        src.off = i;
        dst.off = i;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }

    src.val.la = op1;

    for (int i = 0; i < bytes1; i++){
        src.off = i;
        //Hardcode 8 bytes because first element is always 64 bits
        dst.off = i + 8*idx;
        op.val.copy.a = src;
        op.val.copy.b = dst;
        tob_op_write(tbuf, &op);
    }
}

void PandaTaintVisitor::visitLandingPadInst(LandingPadInst &I){}

// Unhandled
void PandaTaintVisitor::visitInstruction(Instruction &I){
    printf("Error: Unhandled instruction\n");
    assert(1==0);
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
