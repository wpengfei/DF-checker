/*
 * DoubleFetchChecker-linux.cpp
 *
 *  Created on: 2016年3月10日
 *      Author: wpf
 */

/*
 * DoubleFetchChecker.cpp
 *
 *  Created on: 2015年10月26日
 *      Author: wpf
 *
 * This is the implementation file of double-fetch checker, which should be put in the
 * directory lib/StaticAnalyzer/Checkers
 *
 */

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/StmtVisitor.h"


#include <iostream>
#include <list>
#include "TaintStructs.h"



using namespace clang;
using namespace ento;
namespace {




class DoubleFetchChecker : public Checker<check::Location,
										check::Bind,
										check::PreCall,
										check::PostCall,
										check::PostStmt<Expr>,
										check::PreStmt<Expr>,
										check::PreStmt<CallExpr>,
										check::PostStmt<CallExpr>,
										check::BranchCondition,
										check::EndFunction,
										check::EndAnalysis,
										check::ASTDecl<FunctionDecl>
										> {
private:
	std::unique_ptr<BugType> DoubleFetchType;
	mutable SyscallTable syscalls;
	mutable FuncList funcs;
	mutable unsigned int maxTag;
	mutable unsigned int curTime;
public:
	DoubleFetchChecker();
	void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
	//void checkPreStmt(const BlockExpr *BE, CheckerContext &Ctx) const;
	void checkPostStmt(const BlockExpr *BE, CheckerContext &Ctx) const;

	void checkPreCall(const CallEvent &Call,CheckerContext &Ctx) const;
	void checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const;

	void checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const;
	void checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const;

	void checkPreStmt(const Expr *E, CheckerContext &Ctx) const;
	void checkPostStmt(const Expr *E, CheckerContext &Ctx) const;

	void checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const;
	void checkLocation(SVal loc, bool isLoad, const Stmt* LoadS, CheckerContext &Ctx) const;
	void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;

	void checkEndFunction(CheckerContext &Ctx) const;
	void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx, ExplodedNode * Node, SourceRange r,SVal val) const;

	SymbolRef getSymbolRef(SVal val) const;
	unsigned int getNewTag() const;
	unsigned int genTimeStamp() const;

	unsigned int getTaint(SVal val, ProgramStateRef state)const;
	bool isElement(const MemRegion* mrptr, ProgramStateRef state) const;
	bool isDereference(const Stmt* LoadS ) const;
	const MemRegion * getBaseRegion(ProgramStateRef state, SVal sub, std::string funcName)const;
}; //class end
}// namespace end

unsigned int total = 0;
std::string prefix = "";

REGISTER_LIST_WITH_PROGRAMSTATE(AccessList, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(RegionMap, const MemRegion *,STATE)
//REGISTER_MAP_WITH_PROGRAMSTATE(TestMap, SVal, STATE)
REGISTER_TRAIT_WITH_PROGRAMSTATE(MaxTaint, unsigned int)
REGISTER_TRAIT_WITH_PROGRAMSTATE(Depth, unsigned int)

DoubleFetchChecker::DoubleFetchChecker(){
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
	this->maxTag = 0;
	this->curTime = 1;
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	std::string func =  D->getNameAsString();
	bool issys = this->syscalls.isSysFunc(func);

	std::string arg;
	int argNum = D->getNumParams();
	for (int i = 0; i < argNum; i++ ){
		arg = D->parameters()[i]->getQualifiedNameAsString();
		if(arg == "")
			return;
		if(D->parameters()[i]->getType()->isPointerType()){
			ARG a(func, arg, true, issys);
			this->funcs.Add(a);
			//if (DEBUG)
			//flog<<"===> checkASTDecl <=== funcName:"<<func<<"\targName:"<<arg<<"\tisPtr:"<<true<<"\tisSys:"<<issys<<std::endl;
		}
		else{
			ARG a(func, arg, false, issys);
			this->funcs.Add(a);
			//if (DEBUG)
			//flog<<"===> checkASTDecl <=== funcName:"<<func<<"\targName:"<<arg<<"\tisPtr:"<<false<<"\tisSys:"<<issys<<std::endl;
		}

	}
	//funcRet = D->getReturnType().getAsString();
	//Stmt* body = D->getBody();
	//this->AL.showArgs();
}





void DoubleFetchChecker::checkPreStmt(const Expr* E, CheckerContext &Ctx) const {

}
void DoubleFetchChecker::checkPostStmt(const Expr* E, CheckerContext &Ctx) const {

}

void DoubleFetchChecker::checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const{

}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{

}
unsigned int DoubleFetchChecker::genTimeStamp() const{
	this->curTime ++;
	//printf("new tag is %d\n", this->maxTag);
	return this->curTime;
}

unsigned int DoubleFetchChecker::getNewTag()const{
	this->maxTag ++;
	//printf("new tag is %d\n", this->maxTag);
	return this->maxTag;
}
unsigned int DoubleFetchChecker::getTaint(SVal val, ProgramStateRef state)const{
	for(unsigned int i= 0; i <= this->maxTag; i++){
		//printf("ssaa%d\n",i);
		if(state->isTainted(val,i)){
			//printf("ss%d\n",i);
			return i;
		}
	}
	return 0;
}

inline bool DoubleFetchChecker::isDereference(const Stmt* LoadS) const{

	const Expr *ep = dyn_cast<Expr>(LoadS);
	if(!ep){
		return false;
		fout<<"[isDereference()] "<<"get Expr failed!\n";
	}
	if(	ep->getType()->isPointerType())
		return false;
	else{
		return true;
	}


}

void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	if (DEBUG)
		fout<<"\n";

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();

	if (DEBUG)
		fout<<"[checkBind()] funcName: "<<funcName<<std::endl;

	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		if (DEBUG)
			fout<<"[checkBind()] get MemRegion failed!\n";
		return;
	}
	std::string locStr = mrptr->getString();
	SVal locval = state->getSVal(mrptr);
	if (DEBUG)
		fout<<"[checkBind()] locName: "<<locStr<<"\tlocVal: "<<toStr(locval)<<"\tbind value: "<<toStr(val)<<std::endl;



	/*
	const Expr *ep = dyn_cast<Expr>(StoreE);
	if(!ep){
		fout<<"get expr failed \n";
		return;
	}
	*/

	//bool isptr = ep->getType()->isPointerType();
	//fout<<"[checkBind()] isPointer: "<<isptr<<std::endl;

	unsigned int taint = this->getTaint(val, state);

	unsigned int time  = this->genTimeStamp();

	const STATE *s = state->get<RegionMap>(mrptr);
	if (s){
		state = state->remove<RegionMap>(mrptr);
		if (DEBUG)
			fout<<"----[checkBind()] local region already in the RegionMap, remove before add\n";
		STATE st(funcName,locStr,val, 0, taint, true, false, false, time);
		state = state->set<RegionMap>(mrptr, st);
		if (DEBUG)
			st.showState("----[checkBind()] update state ==> ");
	}
	else{//STATE(name,locVal,count,taint,islocal, isPtr, isBase)>
		if (DEBUG)
			fout<<"----[checkBind()] add new local to the RegionMap\n";
		STATE st(funcName, locStr,val, 0, taint, true, false,false, time);
		state = state->set<RegionMap>(mrptr, st);
		if (DEBUG)
			st.showState("----[checkBind()] new state ==> ");
	}

	Ctx.addTransition(state);

}

const MemRegion * DoubleFetchChecker::getBaseRegion(ProgramStateRef state, SVal sub, std::string funcName)const{
	RegionMapTy RM = state->get<RegionMap>();
	if(RM.isEmpty()){
		if (DEBUG)
			fout<<"----[getBaseRegion()] get RegionMapTy failed.\n";
		return NULL;
	}
	RegionMapTy::iterator I = RM.begin();
	RegionMapTy::iterator E = RM.end();

	const MemRegion* subregion = sub.getAsRegion();

	if(!subregion){
		if (DEBUG)
			fout<<"----[getBaseRegion()] get subregion failed.\n";
		return NULL;
	}
	unsigned int temp = 0;
	RegionMapTy::iterator ret = RM.end();

	for (I = RM.begin(); I!=E; I++){
		if((*I).second.isBasePtr() ){//&& (*I).second.getFuncName() == funcName
			SVal base = state->getSVal((*I).first);
			const MemRegion* baseregion = base.getAsRegion();
			if(!baseregion){
				if (DEBUG)
					fout<<"----[getBaseRegion()] get baseregion failed.\n";
				return NULL;
			}

			if (DEBUG)
				fout<<"----[getBaseRegion()] "<<(*I).second.getFuncName()<<std::endl;

			if(subregion->isSubRegionOf(baseregion) || subregion == baseregion){
				if (DEBUG)
					fout<<"----[getBaseRegion()] "<<subregion->getString()<<" is subregion of: "<<baseregion->getString()<<"timestamp: "<<(*I).second.getTimeStamp()<<std::endl;
				if(temp == 0){
					temp = (*I).second.getTimeStamp();
					ret = I;
				}
				else if((*I).second.getTimeStamp() < temp){
					temp = (*I).second.getTimeStamp();
					ret = I;
				}
			}
			else{
				if (DEBUG)
					fout<<"----[getBaseRegion()] "<<subregion->getString()<<" is not subregion of: "<<baseregion->getString()<<std::endl;

			}
		}
	}
	if(ret != RM.end())
		return (*ret).first;
	else
		return NULL;

}
void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	if (DEBUG)
		fout<<"\n";
	bool fire = false;
	ProgramStateRef state = Ctx.getState();

	unsigned int d = state->get<Depth>();
	if (DEBUG)
		fout<<"depth =:"<<d<<std::endl;

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	if (DEBUG)
		fout<<"[checkLocation()] funcName: "<<funcName<<std::endl;
	if(funcName == "__get_user" || funcName == "copy_from_user"){
		if (DEBUG)
			fout<<"[checkLocation()] data transfer funcs!!!"<<std::endl;
	}
	//llvm::errs() << "[checkLocation] get funcName: " << funcName << '\n';

	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		if (DEBUG)
			fout<<"[checkLocation()] get MemRegion failed!\n";
		return;
	}

	SVal locVal= state->getSVal(mrptr);
	std::string locName = mrptr->getString();


	if (isLoad){
		if (DEBUG){
			fout<<"[checkLocation()] "<<" (read)";
			fout<<"\tlocName: "<<locName<<"\tlocVal: "<<toStr(locVal)<<std::endl;
		}
	}
	else{
		if (DEBUG){
			fout<<"[checkLocation()] "<<" (write)";
			fout<<"\tlocName: "<<locName<<"\tlocVal: "<<toStr(locVal)<<std::endl;
		}
		return;// neglect write temporary
	}



	bool isSyscallPtr = false;
	bool isSyscallNPtr = false;
	bool isInSyscall = false;
	bool isInnerFuncPtr = false;
	bool isInnerFuncNPtr = false;
	bool isInInnerFunc = false;
	bool isInRegionMap = false;
	bool isTainted = false;
	bool isLocal = false;
	bool isSubregion = false;
	bool isPtr = false;

	isSyscallPtr = this->funcs.containsSysPtrArg(locName, funcName);
	isSyscallNPtr = this->funcs.containsSysNPtrArg(locName, funcName);
	isInSyscall = this->syscalls.isSysFunc(funcName);

	isInnerFuncPtr = this->funcs.containsPtrArg(locName,funcName);
	isInnerFuncNPtr = this->funcs.containsNPtrArg(locName,funcName);
	isInInnerFunc = this->funcs.containsFunc(funcName);

	const STATE* os = state->get<RegionMap>(mrptr);
	if(os){
		isInRegionMap = true;
		isLocal = os->isLocal();
	}
	else{
		isInRegionMap = false;
		isLocal = false;
	}

	unsigned int taint = this->getTaint(locVal, state);
	unsigned int time  = this->genTimeStamp();

	if(taint > 0)
		isTainted = true;
	else
		isTainted = false;

	const Expr *ep = dyn_cast<Expr>(LoadS);
	isPtr = ep->getType()->isPointerType();

	if (DEBUG){
		fout<<"--->[checkLocation()] isSyscallPtr: "<<isSyscallPtr<<std::endl;
		fout<<"--->[checkLocation()] isSyscallNPtr: "<<isSyscallNPtr<<std::endl;
		fout<<"--->[checkLocation()] isInSyscall: "<<isInSyscall<<std::endl;

		fout<<"--->[checkLocation()] isInnerFuncPtr: "<<isInnerFuncPtr<<std::endl;
		fout<<"--->[checkLocation()] isInnerFuncNPtr: "<<isInnerFuncNPtr<<std::endl;
		fout<<"--->[checkLocation()] isInInnerFunc: "<<isInInnerFunc<<std::endl;
		fout<<"--->[checkLocation()] isInRegionMap: "<<isInRegionMap<<std::endl;
		fout<<"--->[checkLocation()] isLocal: "<<isLocal<<std::endl;
		fout<<"--->[checkLocation()] isTainted: "<<isTainted<<std::endl;
		fout<<"--->[checkLocation()] isPtr: "<<isPtr<<std::endl;
		fout<<"------------------"<<std::endl;
	}


	//syscall func user-ptr arg
	if(isSyscallPtr){
		if (DEBUG)
			fout<<"--->[checkLocation()] isSysCall ptr.\n";
		if(isInRegionMap){
			if (DEBUG)
				os->showState("--->[checkLocation()][syscall ptr], accessed before, already in the RegionMap ==>");
			return;
		}
		else{
			if(isTainted){
				if (DEBUG)
					fout<<"--->[checkLocation()] syscall ptr tainted, is passed from upper func.\n";
				SymbolRef ref = this->getSymbolRef(locVal);
				if(!ref){
					if (DEBUG)
						fout<<"--->[checkLocation()] get symbolref failed\n";
					return;
				}
				state = state->addTaint(ref,taint);
				STATE st(funcName, locName, locVal, 0, taint, false, isPtr, true, time);
				if (DEBUG)
					st.showState("--->[checkLocation()] new syscall ptr, taint again and add to RegionMap ==>");
				state = state->set<RegionMap>(mrptr,st);
				Ctx.addTransition(state);

				return;
			}
			else{
				if (DEBUG)
					fout<<"--->[checkLocation()] syscall ptr untainted, is top func.\n";
				//add taint
				taint = this->getNewTag();
				SymbolRef ref = this->getSymbolRef(locVal);
				if(!ref){
					if (DEBUG)
						fout<<"--->[checkLocation()] get symbolref failed\n";
					return;
				}
				state = state->addTaint(ref,taint);
				//add to RegionMap
				//STATE(funcName, locName,locVal,count,taint,islocal, isPtr, isBase, timestamp)>
				STATE st(funcName, locName, locVal, 0, taint, false, isPtr, true, time);
				if (DEBUG)
					st.showState("--->[checkLocation()] syscall ptr, taint and add to RegionMap ==>");
				state = state->set<RegionMap>(mrptr,st);

				flog<<"\n";
				flog<<"[top ptr] funcName: "<<funcName<<"\tlocName: "<<locName;
				flog<<"\t[base ptr] \tfuncName: "<<st.getFuncName()<<"\t\tlocName: "<<st.getLocName()
						<<"\tcount: "<<st.getCount()<<"\ttaint: "<<st.getTaint()
						<<"\ttime: "<<st.getTimeStamp()<<std::endl;

				Ctx.addTransition(state);
				return;
			}
		}

	}
	if(isSyscallNPtr){
		if (DEBUG)
			fout<<"--->[checkLocation()] isSysCallNptr, return.\n";
		return;
	}

	//syscall func with non-uptr
	if(!isSyscallPtr && !isSyscallNPtr && isInSyscall){
		if (DEBUG)
			fout<<"--->[checkLocation()] is in sys_call func, but not ptr or nptr\n";
		if(isInRegionMap && isLocal){
			if (DEBUG)
				fout<<"--->[checkLocation()] "<<"In RegionMap, is local Region\n";
			//tainted
			//pointer
			return;
		}
		//dereference
		if(isTainted){
			if (DEBUG)
				fout<<"--->[checkLocation()] tainted subregion dereference\n";
			flog<<"--->[checkLocation()] tainted subregion dereference\n";

			const MemRegion * base = getBaseRegion(state, loc, funcName);
			if(!base){
				if (DEBUG)
					fout<<"--->[checkLocation()] get base failed\n";
				return ;
			}
			const STATE* bs = state->get<RegionMap>(base);
			if(!bs){
				if (DEBUG)
					fout<<"--->[checkLocation()] get state failed\n";
				return ;
			}
			state = state->set<RegionMap>(base,bs->getAsIncre());
			if (DEBUG)
				bs->getAsIncre().showState("--->[checkLocation()]  base region count+1 ==> ");



			//====>file
			flog<<"\n";
			for (int i =0; i<=d; i++){
				flog<<"<<<<";
			}
			flog<<" funcName: "<<funcName<<"\tlocName: "<<locName;
			flog<<"\t[base ptr] \tfuncName: "<<bs->getAsIncre().getFuncName()<<"\t\tlocName: "<<bs->getAsIncre().getLocName()
					<<"\tcount: "<<bs->getAsIncre().getCount()<<"\ttaint: "<<bs->getAsIncre().getTaint()
					<<"\ttime: "<<bs->getAsIncre().getTimeStamp();

			ExplodedNode *Node = Ctx.addTransition(state);

			if(bs->getAsIncre().getCount() > 1){
				SourceRange sr(LoadS->getLocStart(), LoadS->getLocEnd());
				this->reportDoubleFetch(Ctx, Node, sr, loc);

				if (DEBUG)
					fout<<"--->[checkLocation()] Fire DF!!\n";

				flog<<"\t[DF]\n";
			}
			else
				flog<<"\n";
			return;
		}
		//none-pointer args
		else{
			if (DEBUG)
				fout<<"--->[checkLocation()] is untainted in syscall, return.\n";
			return;
		}
	}


	// innerFunctions

	if(isInnerFuncPtr && isTainted){
		if (DEBUG)
			fout<<"--->[checkLocation()] is innerFunc ptr\n";
		if(isInRegionMap){
			if (DEBUG)
				fout<<"--->[checkLocation()] innerFunc ptr tainted, already in RegionMap??.\n";
			return;
		}
		else{
			SymbolRef ref = this->getSymbolRef(locVal);
			if(!ref){
				if (DEBUG)
					fout<<"--->[checkLocation()] get symbolref failed\n";
				return;
			}
			state = state->addTaint(ref,taint);
			//STATE(funcName, locName,locVal,count,taint,islocal, isPtr, isBase, timestamp)>
			STATE st(funcName, locName, locVal, 0, taint, false, isPtr, true, time);
			if (DEBUG)
				st.showState("--->[checkLocation()] tainted new  pointer in innerFunc, add to RegionMap ==>");
			state = state->set<RegionMap>(mrptr,st);
			ExplodedNode *Node = Ctx.addTransition(state);
			return;
		}
	}
	//
	if(isInnerFuncNPtr){
		if (DEBUG)
			fout<<"--->[checkLocation()] isisInnerFuncNPtr, return\n";
		return;
	}

	//innerFunc
	if(!isInnerFuncPtr && !isInnerFuncNPtr && isInInnerFunc){
		if (DEBUG)
			fout<<"--->[checkLocation()] isInInnerFunc\n";
		if(isInRegionMap && isLocal){
			if (DEBUG)
				fout<<"--->[checkLocation()] "<<"In RegionMap, is local Region\n";
			//tainted
			//pointer
			return;
		}

		//dereference
		if(isTainted){


			if (DEBUG)
				fout<<"--->[checkLocation()] innerFunc dereference\n";
			flog<<"--->[checkLocation()] innerFunc dereference\n";

			const MemRegion * base = getBaseRegion(state, loc, funcName);
			if(!base){
				if (DEBUG)
					fout<<"--->[checkLocation()] get base failed\n";
				return ;
			}
			const STATE* bs = state->get<RegionMap>(base);
			if(!bs){
				if (DEBUG)
					fout<<"--->[checkLocation()] get state failed\n";
				return ;
			}
			state = state->set<RegionMap>(base,bs->getAsIncre());
			if (DEBUG)
				bs->getAsIncre().showState("--->[checkLocation()]  base region count+1 ==> ");

			//====>file
			flog<<"\n";
			for (int i =0; i<=d; i++){
				flog<<"<<<<";
			}

			flog<<" funcName: "<<funcName<<"\tlocName: "<<locName;
			flog<<"\t[base ptr] \tfuncName: "<<bs->getAsIncre().getFuncName()<<"\t\tlocName: "<<bs->getAsIncre().getLocName()
					<<"\tcount: "<<bs->getAsIncre().getCount()<<"\ttaint: "<<bs->getAsIncre().getTaint()
					<<"\ttime: "<<bs->getAsIncre().getTimeStamp();

			ExplodedNode *Node = Ctx.addTransition(state);
			if(bs->getAsIncre().getCount() > 1){
				SourceRange sr(LoadS->getLocStart(), LoadS->getLocEnd());
				this->reportDoubleFetch(Ctx, Node, sr, loc);
				fout<<"--->[checkLocation()] Fire DF!!\n";
				flog<<"\t[DF]\n";
			}
			else
				flog<<"\n";
			return;
		}
		//none-pointer args
		else{
			if (DEBUG)
				fout<<"--->[checkLocation()] innerFunc untainted var, error. return.\n";
			return;
		}
	}




}

void DoubleFetchChecker::checkBranchCondition(const Stmt *Condition,
	CheckerContext &Ctx) const {

}
void DoubleFetchChecker::checkPreCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	ProgramStateRef state = Ctx.getState();
	if (ID == NULL) {
		return;
	}
	if (DEBUG)
		fout<<"[checkPreCall]=======call function: "<<ID->getName().str()<<std::endl;
	if(this->funcs.containsFunc(ID->getName().str())){

		unsigned int d = state->get<Depth>();
		d++;
		state = state->set<Depth>(d);
		Ctx.addTransition(state);
		if (DEBUG)
			fout<<"[checkPreCall]=======enter new func, depth= "<<d<<" \n";
	}


}
void DoubleFetchChecker::checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();

	ProgramStateRef state = Ctx.getState();
	if(ID == NULL) {
		return;
	}

	if (DEBUG)
		fout<<"[checkPostCall]=======call function: "<<ID->getName().str()<<std::endl;


}
void DoubleFetchChecker::reportDoubleFetch(CheckerContext &Ctx, ExplodedNode * Node, SourceRange r, SVal val) const {
	// We reached a bug, stop exploring the path here by generating a sink.
	ExplodedNode *ErrNode = Ctx.generateErrorNode(Ctx.getState());
	// If we've already reached this node on another path, return.
	if (!ErrNode)
		return;


	//DoubleFetchType.reset(new BuiltinBug(this, "Assignment of a non-Boolean value"));
	// Generate the report.
	auto R = llvm::make_unique<BugReport>(*DoubleFetchType,
			"second read of DF", ErrNode);
	//R->addRange(r);
	//R->addExtraText("test");
	//R->markInteresting(val);
	Ctx.emitReport(std::move(R));
}

void DoubleFetchChecker::checkEndFunction(CheckerContext &Ctx) const {

	if (DEBUG)
		fout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;

	ProgramStateRef state = Ctx.getState();

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	if (DEBUG)
		fout<<"[checkEndFunction]funcName:  "<<funcName<<std::endl;



	if(this->funcs.containsFunc(funcName)){
		unsigned int d = state->get<Depth>();
		d--;
		if(d<0){
			if (DEBUG)
				fout<<"[checkEndFunction] d<0 \n";
			d=0;
		}
		state = state->set<Depth>(d);
		Ctx.addTransition(state);
		if (DEBUG)
			fout<<"[checkEndFunction] leave func, depth= "<<d<<" \n";

	}

/*
	RegionMapTy RM = state->get<RegionMap>();
	RegionMapTy::iterator I = RM.begin();
	RegionMapTy::iterator E = RM.end();
	for (I=RM.begin(); I!=E; I++){
		fout<<">>>> location: "<<(*I).first->getString();
		(*I).second.showState();
	}
	AccessListTy AC = state->get<AccessList>();
	AccessListTy::iterator  S = AC.begin();
	AccessListTy::iterator  T = AC.end();
	SVal l;

	for(S = AC.begin(); S != T; ++S){
		fout<<">>>> AccessList: "<<toStr(*S)<<std::endl;
    }
*/
	if (DEBUG)
		fout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;


}
void DoubleFetchChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	if (DEBUG)
		fout<<"[checkEndAnalysis]------------%%%%%%%%%%%%%%%%%%%%%-----------"<<std::endl;
	flog<<"===================================================================================="<<std::endl;
	this->maxTag = 0;
}

SymbolRef DoubleFetchChecker::getSymbolRef(SVal val) const {
	if(val.isConstant()){
		if (DEBUG)
			fout<<"(getSymbolRef) val failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		if (DEBUG)
			fout<<"(getSymbolRef) val failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	const SymExpr * SE = val.getAsSymExpr();
	if (!SE){
		if (DEBUG)
			fout<<"(getSymbolRef) getAsSymExpr failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		//return NULL;
	}
	else
		return SE;

	const MemRegion *Reg = val.getAsRegion();
	if(!Reg){
		if (DEBUG)
			fout<<"(getSymbolRef) getAsRegion failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(Reg)){
			if (DEBUG)
				fout<<"(getSymbolRef) getAsRegion succeed."<<std::endl;
			return SR->getSymbol();
		}

	}

}
void ento::registerDoubleFetchChecker(CheckerManager &mgr) {
	mgr.registerChecker<DoubleFetchChecker>();
}




