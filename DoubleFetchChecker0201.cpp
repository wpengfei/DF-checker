/*
 * DoubleFetchChecker0201.cpp
 *
 *  Created on: 2016年2月1日
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
	mutable ArgsList AL;

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
	void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;


	// my own functions
	void reportDoubleFetch(CheckerContext &Ctx, ExplodedNode * Node, SourceRange r,SVal val) const;

	SymbolRef getSymbolRef(SVal val) const;
	unsigned int getNewTag() const;
	unsigned int getTaint(SVal val, ProgramStateRef state)const;
	bool isElement(const MemRegion* mrptr, ProgramStateRef state) const;
	bool isDereference(const Stmt* LoadS ) const;
}; //class end
}// namespace end


REGISTER_LIST_WITH_PROGRAMSTATE(AccessList, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(RegionMap, const MemRegion *,STATE)
//REGISTER_MAP_WITH_PROGRAMSTATE(TestMap, SVal, STATE)
REGISTER_TRAIT_WITH_PROGRAMSTATE(MaxTaint, unsigned int)

DoubleFetchChecker::DoubleFetchChecker(){
	// Initialize the bug types.
	DoubleFetchType.reset(new BugType(this, "Double Fetch", "Unix kernel TOCTOU Error"));
	// Sinks are higher importance bugs as well as calls to assert() or exit(0).
	//DoubleFetchType->setSuppressOnSink(true);
	this->maxTag = 0;
}

void DoubleFetchChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	std::string func =  D->getNameAsString();
	if (func.find("sys_") == 0)
		std::cout<<"=> sys func: "<<func<<std::endl;
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
	//this->AL.showArgs();
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
bool DoubleFetchChecker::isElement(const MemRegion* mrptr, ProgramStateRef state) const{

	AccessListTy AC = state->get<AccessList>();
	if(AC.isEmpty()){
		printf("s\n");
		return false;
	}
	AccessListTy::iterator  I = AC.begin();

	SVal loc = *I; //last item stored at the head of the list
	const MemRegion *locRegion = loc.getAsRegion();
	SVal val= state->getSVal(locRegion);


	std::cout<<"----[isElement] lastCheck is: "<<val.getAsRegion()->getString()<<std::endl;
	if(mrptr->isSubRegionOf(val.getAsRegion())){

		const STATE* s = state->get<RegionMap>(mrptr);

		std::cout<<"----[isElement] "<<mrptr->getString()<<" is subregion of: "<<val.getAsRegion()->getString()<<std::endl;
		return true;
	}


	return false;
}
/*
bool DoubleFetchChecker::isDereference(std::string locVal ) const{
	if(locVal.find("reg_") == 0)
		return true;
	if(locVal.find("element") != std::string::npos )
		return true;
	return false;

}
*/
inline bool DoubleFetchChecker::isDereference(const Stmt* LoadS) const{

	const Expr *ep = dyn_cast<Expr>(LoadS);
	if(!ep){
		return false;
		std::cout<<"[isDereference()] "<<"get Expr failed!\n";
	}
	if(	ep->getType()->isPointerType())
		return false;
	else{
		return true;
	}


}

void DoubleFetchChecker::checkBind(SVal loc, SVal val,const Stmt *StoreE,CheckerContext &Ctx) const{

	ProgramStateRef state = Ctx.getState();
	printf("\n");
	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	std::cout<<"[checkBind()] funcName: "<<funcName<<std::endl;

	const MemRegion *mrptr = loc.getAsRegion();



	if (!mrptr){
		std::cout<<"[checkBind()] get MemRegion failed!\n";
			return;
	}
	std::string locStr = mrptr->getString();
	SVal locval = state->getSVal(mrptr);
	std::cout<<"[checkBind()] locName: "<<locStr<<"\tlocVal: "<<toStr(locval)<<"\tbind value: "<<toStr(val)<<std::endl;

	unsigned int taint = this->getTaint(val, state);

	/*
	const Expr *ep = dyn_cast<Expr>(StoreE);
	if(!ep){
		std::cout<<"get expr failed \n";
		return;
	}
	*/

	//bool isptr = ep->getType()->isPointerType();
	//std::cout<<"[checkBind()] isPointer: "<<isptr<<std::endl;

	const STATE *s = state->get<RegionMap>(mrptr);
	if (s){
		state = state->remove<RegionMap>(mrptr);
		std::cout<<"----[checkBind] local region already in the RegionMap, remove before add\n";
		STATE st(locStr,val, 0, taint, true, false);
		state = state->set<RegionMap>(mrptr, st);
		std::cout<<"----[checkBind] location is:"<<locStr<<"\tis local var \talready in RegionMap"<<std::endl;
	}
	else{
		std::cout<<"----[checkBind] add new local to the RegionMap\n";
		STATE st(locStr,val, 0, taint, true, false);
		state = state->set<RegionMap>(mrptr, st);
		st.showState("----[checkBind] ");
	}

	Ctx.addTransition(state);


}
void DoubleFetchChecker::checkLocation( SVal loc, bool isLoad, const Stmt* LoadS,
	CheckerContext &Ctx) const{

	printf("\n");
	bool fire = false;
	ProgramStateRef state = Ctx.getState();

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	std::cout<<"[checkLocation()] funcName: "<<funcName<<std::endl;
	//llvm::errs() << "[checkLocation] get funcName: " << funcName << '\n';

	const MemRegion *mrptr = loc.getAsRegion();
	if (!mrptr){
		std::cout<<"[checkLocation()] get MemRegion failed!\n";
		return;
	}

	SVal locVal= state->getSVal(mrptr);
	std::string locName = mrptr->getString();


	if (isLoad){
		std::cout<<"[checkLocation()] "<<" (read)";
		std::cout<<"\tlocName: "<<locName<<"\tlocVal: "<<toStr(locVal)<<std::endl;
	}
	else{
		std::cout<<"[checkLocation()] "<<" (write)";
		std::cout<<"\tlocName: "<<locName<<"\tlocVal: "<<toStr(locVal)<<std::endl;
		return;// neglect write temporary
	}

	const Expr *ep = dyn_cast<Expr>(LoadS);
	bool isptr = ep->getType()->isPointerType();

	//check if is user pointer
	if(AL.contains(locName, funcName)){
		// user pointer, taint first
		const STATE* s = state->get<RegionMap>(mrptr);
		if(!s){
			//first reference
			unsigned int nt = this->getNewTag();
			SymbolRef ref = this->getSymbolRef(locVal);
			if(!ref){

				std::cout<<"--->[checkLocation()] get symbolref failed\n";
				return;
			}

			state = state->addTaint(ref,nt);
			//then add to region map, RegionMap<MemRegion*, STATE(name,base,count,taint)>
			STATE st(locName, locVal, 0, nt, false, isptr);
			st.showState("--->[checkLocation()] new user pointer, add new loc to RegionMap ");
			state = state->set<RegionMap>(mrptr,st);
		}
		else{
			s->showState("--->[checkLocation()] user pointer,already in the RegionMap ");
		}
	}
	//non-pointer or local region, or  region during referencing
	else{
		std::cout<<"--->[checkLocation()] "<<"not recored args\n";
		unsigned int tainted = this->getTaint(locVal, state);
		//region during referencing
		if(tainted){
			std::cout<<"--->[checkLocation()] "<<"tainted, sub region of user pointer region, or local Region assigned by user region\n";
			const STATE* s = state->get<RegionMap>(mrptr);
			if(!s){
				//first reference
				//then add to region map, RegionMap<MemRegion*, STATE(name,base,count,taint)>

				STATE st(locName, locVal, 0, tainted, false, isptr);
				st.showState("--->[checkLocation()]  add new referencing region to RegionMap ");
				state = state->set<RegionMap>(mrptr,st);
			}
			else{
				s->showState("--->[checkLocation()] region already in the RegionMap ");
				if (s->isLocal()){
					std::cout<<"--->[checkLocation()] "<<"is local\n";
				}
				else{
					std::cout<<"--->[checkLocation()] "<<"is referencing region\n";
				}
			}

		}
		else{
			std::cout<<"--->[checkLocation()] "<<"untainted, local region or none pointer, do not recored in RegionMap\n";
		}
	}

	std::cout<<"------>[checkLocation()] "<<"checking dereference: \n";
	if(isDereference(LoadS)){

		std::cout<<"------>[checkLocation()] "<<"is dereference\n";

		unsigned int tainted = this->getTaint(locVal, state);
		if(tainted){
			std::cout<<"------>[checkLocation()] "<<"is tainted\n";
			const STATE* s = state->get<RegionMap>(mrptr);
			if(s){
				if (!s->isLocal()){
					state = state->set<RegionMap>(mrptr,s->getAsIncre());
					s->getAsIncre().showState("------>[checkLocation()] count+1 ");
					if (s->getAsIncre().getCount() > 1){
						std::cout<<"------>[checkLocation()] "<<"fire DF!\n";
						fire = true;
					}
				}
				else{
					if(!isptr)
						std::cout<<"------>[checkLocation()] is local region, && not ptr, abandon.\n";
				}
			}
			else{
				std::cout<<"------>[checkLocation()] should be error\n";
			}
		}
		else{
			std::cout<<"------>[checkLocation()] should be non-pointer\n";
		}

	}
	else{
		std::cout<<"------>[checkLocation()] "<<"not dereference\n";

	}



	/*
	std::cout<<"------>[checkLocation()] "<<"checking dereference: \n";
	if(isDereference(LoadS)){

		std::cout<<"------>[checkLocation()] "<<"is dereference\n";

		unsigned int tainted = this->getTaint(locVal, state);
		if(tainted){
			const STATE* s = state->get<RegionMap>(mrptr);
			if(s){
				if (!s->isLocal()){
					state = state->set<RegionMap>(mrptr,s->getAsIncre());
					s->getAsIncre().showState("------>[checkLocation()] count+1 ");
					if (s->getAsIncre().getCount() > 1){
						std::cout<<"------>[checkLocation()] "<<"fire DF!\n";
						fire = true;
					}
				}
				else{
					if(!isptr)
						std::cout<<"------>[checkLocation()] is local region, && not ptr, abandon.\n";
				}
			}
			else{

				STATE s(locName, locVal, 1, tainted, false, isptr);
				s.showState("------>[checkLocation()] add new state to RegionMap ");
				state = state->set<RegionMap>(mrptr,s);

				std::cout<<"------>[checkLocation()] should be error\n";
			}
		}

	}
	else{
		std::cout<<"------>[checkLocation()] "<<"not dereference\n";

	}
	*/


	ExplodedNode *Node = Ctx.addTransition(state);

	if(fire){
		SourceRange sr(LoadS->getLocStart(), LoadS->getLocEnd());

		this->reportDoubleFetch(Ctx, Node, sr, loc);

	}

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
	std::cout<<"[checkPreCall]========call function: "<<ID->getName().str()<<std::endl;


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
	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;

	const LocationContext *LC = Ctx.getLocationContext();
	const Decl *D = LC->getAnalysisDeclContext()->getDecl();
	const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
	std::string funcName = FD->getNameAsString();
	std::cout<<"[checkEndFunction]funcName:  "<<funcName<<std::endl;

	ProgramStateRef state = Ctx.getState();
	RegionMapTy RM = state->get<RegionMap>();
	RegionMapTy::iterator I = RM.begin();
	RegionMapTy::iterator E = RM.end();
	for (I=RM.begin(); I!=E; I++){
		std::cout<<">>>> location: "<<(*I).first->getString();
		(*I).second.showState();
	}
	AccessListTy AC = state->get<AccessList>();
	AccessListTy::iterator  S = AC.begin();
	AccessListTy::iterator  T = AC.end();
	SVal l;

	for(S = AC.begin(); S != T; ++S){
		std::cout<<">>>> AccessList: "<<toStr(*S)<<std::endl;
    }

	std::cout<<"[checkEndFunction]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"<<std::endl;


}
void DoubleFetchChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	std::cout<<"[checkEndAnalysis]------------%%%%%%%%%%%%%%%%%%%%%-----------"<<std::endl;
	this->maxTag = 0;
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





