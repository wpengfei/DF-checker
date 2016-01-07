/*
 * DoubleFetchChecker-0107.cpp
 *
 *  Created on: 2016年1月7日
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
										check::ASTDecl<FunctionDecl>
										> {
private:
	std::unique_ptr<BugType> DoubleFetchType;
	mutable ArgsList AL;
	mutable SVal lastCheck;
	mutable unsigned int maxTag;
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



	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx, const CallEvent &Call) const;

	SymbolRef getSymbolRef(SVal val) const;
	unsigned int getNewTag() const;
	bool isElement(const MemRegion* mrptr) const;

}; //class end
}// namespace end

//REGISTER_MAP_WITH_PROGRAMSTATE(TaintsMap, SymbolRef, TaintList)
//REGISTER_SET_WITH_PROGRAMSTATE(BranchTaintSet, TAINT)
REGISTER_MAP_WITH_PROGRAMSTATE(RegionMap, const MemRegion *,STATE)


DoubleFetchChecker::DoubleFetchChecker(){
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
	this->maxTag = 0;
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	std::string func =  D->getNameAsString();
	std::string arg;
	std::string type;
	int argNum = D->getNumParams();
	for (int i = 0; i < argNum; i++ ){
		arg = D->parameters()[i]->getQualifiedNameAsString();
		if(D->parameters()[i]->getType()->isPointerType()){
			type = "pointer";
			ARG a(func, arg, type);
			this->AL.Add(a);
		}
		else
			type = "non-pointer";
		std::cout<<"===> checkASTDecl <=== funcName:"<<func<<"\targName:"<<arg<<"\targType:"<<type<<std::endl;
	}
	//funcRet = D->getReturnType().getAsString();
	//Stmt* body = D->getBody();
	this->AL.showArgs();
}





void DoubleFetchChecker::checkPreStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());

	//SourceManager sm = Ctx.getSourceManager();
	SourceLocation L = E->getExprLoc();
	//std::cout<<"xxxsssssssssssssssssssssssssssssssssssssssss"<<std::endl;
	//std::cout<<"ss"<<L.printToString(Ctx.getSourceManager())<<std::endl;

	//std::cout<<"[checkPreStmt<Expr>] "<<toStr(E)<<std::endl;
/*
	if(!isUntainted(state,ExpVal)){
		std::cout<<"[checkPreStmt<Expr>]"<<"\ttainted, \t ";
		showTaintTags(state, ExpVal);
	}
	 else
		std::cout<<"[checkPreStmt<Expr>] not tainted"<<"\t Expr Sval is:"<<toStr(ExpVal)<<std::endl;
*/


}
void DoubleFetchChecker::checkPostStmt(const Expr* E, CheckerContext &Ctx) const {
	ProgramStateRef state = Ctx.getState();
	SVal ExpVal = state->getSVal(E, Ctx.getLocationContext());
	//if (isa<BlockExpr>(E))
		//std::cout<<"sssssssssssssssssssssssssssssssssssssssss"<<std::endl;
	//std::cout<<"[checkPostStmt<Expr>] "<<toStr(E)<<std::endl;
	/*
	if(!isUntainted(state,ExpVal)){
		std::cout<<"[checkPostStmt<Expr>]"<<"\ttainted, \t ";
		showTaintTags(state, ExpVal);
	}
	 else
		std::cout<<"[checkPostStmt<Expr>] not tainted"<<"\t Expr Sval is:"<<toStr(ExpVal)<<std::endl;
*/

}

void DoubleFetchChecker::checkPreStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);
	//std::cout<<"[checkPreStmt<CallExpr>] func name is:"<<funcName.<<std::endl;
	//printf("[checkPreStmt<CallExpr>] func name is:%s\n",funcName);
	//std::cout<<"-------------------->getLocStart: "<<CE->getLocStart().getRawEncoding()<<std::endl;
	//std::cout<<"--------------------->getLocEnd: "<<CE->getLocEnd().getRawEncoding()<<std::endl;
	//std::cout<<"-------------------->getExprLoc: "<<CE->getExprLoc().getRawEncoding()<<std::endl;


	//std::cout<<"spelling: "<<spelling<<"ex: "<<ex<<std::endl;
	//std::cout<<"str::"<<CE->getExprLoc().printToString(Ctx.getSourceManager())<<std::endl;
}

void DoubleFetchChecker::checkPostStmt(const CallExpr *CE, CheckerContext &Ctx) const{
	ProgramStateRef state = Ctx.getState();
	const FunctionDecl *FDecl = Ctx.getCalleeDecl(CE);
	StringRef funcName = Ctx.getCalleeName(FDecl);
	//std::cout<<"[checkPostStmt<CallExpr>] func name is:"<<funcName<<std::endl;
	//printf("[checkPostStmt<CallExpr>] func name is:%s\n",funcName);

}



void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();

	std::cout<<"[checkBind] "<<"location: "<<toStr(loc)<<"\taccess value: "<<toStr(val)<<std::endl;

	const MemRegion *mrptr = loc.getAsRegion();
	std::string locStr = mrptr->getString();

	if (!mrptr){
		std::cout<<"[checkLocation] get MemRegion failed!\n";
			return;
	}
	const STATE *s = state->get<RegionMap>(mrptr);
	if (s){
		//s->isLocal = true;
		state = state->set<RegionMap>(mrptr, s->getAsLocal());
		std::cout<<"[checkBind] location is:"<<locStr<<"\tis local var \talready in RegionMap"<<std::endl;

	}
	else{
		STATE st(0, true, 0);
		state = state->set<RegionMap>(mrptr, st);
		std::cout<<"[checkBind] location is:"<<locStr<<"\tis local var \tadd new loc to RegionMap"<<std::endl;
	}
	Ctx.addTransition(state);

}
unsigned int DoubleFetchChecker::getNewTag()const{
	this->maxTag ++;
	//printf("new tag is %d\n", this->maxTag);
	return this->maxTag;
}
bool DoubleFetchChecker::isElement(const MemRegion* mrptr) const{
	if (!this->lastCheck.isUnknownOrUndef()){//first time, lastcheck is none
		if(this->lastCheck.getAsRegion()){// symbolic regions
			//std::cout<<"lastCheck is: "<<this->lastCheck.getAsRegion()->getString()<<std::endl;
			if(mrptr->isSubRegionOf(this->lastCheck.getAsRegion())){
				std::cout<<"[isElement] "<<mrptr->getString()<<" is subregion of: "<<this->lastCheck.getAsRegion()->getString()<<std::endl;
				return true;
			}
		}
	}
	return false;
}
void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		std::cout<<"[checkLocation] get MemRegion failed!\n";
			return;
	}
	std::string locStr = mrptr->getString();
	if (isLoad)
		std::cout<<"[checkLocation()] "<<" (read)";
	else{
		std::cout<<"[checkLocation()] "<<" (write)\n";
		return;// neglect write temporary
	}


	SVal val= state->getSVal(mrptr);
	std::cout<<"\tlocation: "<<toStr(loc)<<"\taccess value: "<<toStr(val)<<std::endl;
	//const MemRegion* base = mrptr->getBaseRegion();
	//std::cout<<"base is: "<<base->getString()<<std::endl;



	const STATE* s = state->get<RegionMap>(mrptr);
	if(!s){//new address
		if(AL.contains(locStr)){// user pointer
			STATE st(1, false, this->getNewTag()); //first read, not local var, add new taint
			state = state->set<RegionMap>(mrptr, st);
			std::cout<<"@@@"<<"location is:"<<locStr<<"\tnew user pointer: count 1, none local, tag is"<<this->maxTag<<std::endl;
		}
		else{//none user pointer, maybe element
			if(isElement(mrptr)){
				STATE st(1, false, this->getNewTag()); //first read, not local var, add new taint
				state = state->set<RegionMap>(mrptr, st);
				std::cout<<"@@@"<<"location is:"<<locStr<<"\tnew element of user pointer: count 1, none local, tag is"<<this->maxTag<<std::endl;
			}
			else{
				STATE st(1, true, this->getNewTag()); //first read, not local var, add new taint
				state = state->set<RegionMap>(mrptr, st);
				std::cout<<"@@@"<<"location is:"<<locStr<<"\tnew local var: count 1, local var, tag is"<<this->maxTag<<std::endl;
			}

		}
	}
	else{
		state = state->set<RegionMap>(mrptr,s->getAsIncre());
		const STATE* s1 = state->get<RegionMap>(mrptr);//state updated
		std::cout<<"@@@"<<"location is:"<<locStr<<"\talready in RegionMap.increase count to:"<<s1->getCount()<<"\tislocal:"<<s->isLocal()<<"\ttag is"<<s->getTag()<<std::endl;

		if(s1->isLocal())
			std::cout<<"@@@"<<"abandan check"<<locStr<<std::endl;
		if(!s1->isLocal() && s1->getCount() > 1)
			std::cout<<"@@@@@ "<<" ----DF in----"<<locStr<<std::endl;
	}



	/*

	if(!state->isTainted(val) && AL.contains(locStr) && isLoad){
		state = state->addTaint(this->getSymbolRef(val));
		std::cout<<"[checkLocation()] "<<"==> find function decl Arg, taint the whole mem region of: "<<locStr<<std::endl;

	}

	if(state->isTainted(val) && isLoad){
		std::cout<<"[checkLocation()] "<<"-> read taint value: "<<locStr<<std::endl;

		const STATE* s = state->get<RegionMap>(mrptr);
		if(s){
			unsigned int pre = s->get();
			std::cout<<"[checkLocation()] pre = "<<pre<<std::endl;
			s->increase();
			if(pre > 0){
				std::cout<<"[checkLocation()] !!!!!!!!"<<std::endl;
			}


		}
		else{
			STATE sn(1);
			state = state->set<RegionMap>(mrptr, sn);

			std::cout<<"[checkLocation()] find new element in tainted region: "<<locStr<<std::endl;

		}
	}
	*/


	this->lastCheck = val;
	Ctx.addTransition(state);
}

void DoubleFetchChecker::checkBranchCondition(const Stmt *Condition,
	CheckerContext &Ctx) const {

	ProgramStateRef state = Ctx.getState();



}
void DoubleFetchChecker::checkPreCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();
	ProgramStateRef state = Ctx.getState();
	if (ID == NULL) {
		return;
	}
	std::cout<<"[checkPreCall]-----call function:"<<ID->getName().str()<<std::endl;


	if(ID->getName() == "kernel_func") {
		ProgramStateRef state = Ctx.getState();
		SVal arg = Call.getArgSVal(0);
		const MemRegion* mr = arg.getAsRegion();
		/*
		state = state->add<TaintRegionMap>(mr);
		Ctx.addTransition(state);

		SVal val = state->getSVal(mr);
		ProgramStateRef newstate = addTaintToSymExpr(state, val);
		if(newstate){
			Ctx.addTransition(newstate);
			std::cout<<"[checkPreCall] arg add taint finish: "<<toStr(arg)<<std::endl;
		}
		else
			std::cout<<"[checkPreCall] arg add taint failed: "<<toStr(arg)<<std::endl;
*/
	}


	if (ID->getName() == "__builtin___memcpy_chk") {
		SVal Arg0 = Call.getArgSVal(0);
		SVal Arg1 = Call.getArgSVal(1);
		SVal Arg2 = Call.getArgSVal(2);

		const Expr * erg0 = Call.getArgExpr(0);

		const Expr * erg1 = Call.getArgExpr(1);

		const Expr * erg2 = Call.getArgExpr(2);


	}

}
void DoubleFetchChecker::checkPostCall(const CallEvent &Call,CheckerContext &Ctx) const {
	const IdentifierInfo *ID = Call.getCalleeIdentifier();

	ProgramStateRef state = Ctx.getState();
	if(ID == NULL) {
		return;
	}

	if (ID->getName() == "malloc") {
		SVal arg = Call.getArgSVal(0);
		SVal ret = Call.getReturnValue();

	}


}
void DoubleFetchChecker::reportDoubleFetch(CheckerContext &Ctx, const CallEvent &Call) const {
	// We reached a bug, stop exploring the path here by generating a sink.
	ExplodedNode *ErrNode = Ctx.generateErrorNode(Ctx.getState());
	// If we've already reached this node on another path, return.
	if (!ErrNode)
		return;

	// Generate the report.
	auto R = llvm::make_unique<BugReport>(*DoubleFetchType,
			"Double-Fetch", ErrNode);
	R->addRange(Call.getSourceRange());
	Ctx.emitReport(std::move(R));
}

void DoubleFetchChecker::checkEndFunction(CheckerContext &Ctx) const {
	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;

	ProgramStateRef state = Ctx.getState();
	RegionMapTy RM = state->get<RegionMap>();
	RegionMapTy::iterator I = RM.begin();
	RegionMapTy::iterator E = RM.end();
	for (I=RM.begin(); I!=E; I++){
		std::cout<<">>>> location: "<<(*I).first->getString()<<"\t read count: "<<(*I).second.getCount()<<"\t islocal: "<<(*I).second.isLocal()<<"\ttag: "<<(*I).second.getTag()<<std::endl;
	}



	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;


}


SymbolRef DoubleFetchChecker::getSymbolRef(SVal val) const {
	if(val.isConstant()){
		std::cout<<"(getSymbolRef) val failed! IsConstant."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	if(val.isUnknownOrUndef()){
		std::cout<<"(getSymbolRef) val failed! IsUnknownOrUndef."<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	const SymExpr * SE = val.getAsSymExpr();
	if (!SE){
		std::cout<<"(getSymbolRef) getAsSymExpr failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		//return NULL;
	}
	else
		return SE;

	const MemRegion *Reg = val.getAsRegion();
	if(!Reg){
		std::cout<<"(getSymbolRef) getAsRegion failed!"<<"\tval is:"<<toStr(val)<<std::endl;
		return NULL;
	}
	else{
		if (const SymbolicRegion *SR = dyn_cast_or_null<SymbolicRegion>(Reg)){
			std::cout<<"(getSymbolRef) getAsRegion succeed."<<std::endl;
			return SR->getSymbol();
		}

	}

}
void ento::registerDoubleFetchChecker(CheckerManager &mgr) {
	mgr.registerChecker<DoubleFetchChecker>();
}




