#include "Graphs/SVFG.h"
#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "WPA/TypeAnalysis.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string>
    InputFilename(cl::Positional, llvm::cl::desc("<input bitcode>"),
                  llvm::cl::init("-"));

class GMLCallGraphWriter {
public:
  GMLCallGraphWriter(PTACallGraph *_callGraph) : callGraph(_callGraph) {}

  void dumpToGML(std::string fileName) {
    std::error_code err;
    ToolOutputFile F(fileName.c_str(), err, llvm::sys::fs::F_None);
    if (err) {
      F.os().clear_error();
      return;
    }

    F.os() << "graph \n[\n";
    F.os() << "  directed 1\n\n";
    for (PTACallGraph::iterator it = callGraph->begin(), eit = callGraph->end();
         it != eit; ++it) {
      PTACallGraphNode *node = it->second;
      dumpNode(F.os(), node);
      PTACallGraph::CallGraphEdgeSet outEdges = node->getOutEdges();
      for (PTACallGraph::CallGraphEdgeSet::iterator jt = outEdges.begin(),
                                                    ejt = outEdges.end();
           jt != ejt; ++jt) {
        PTACallGraphEdge *edge = (*jt);
        dumpEdge(F.os(), edge);
      }
    }
    F.os() << "]\n";

    F.os().close();
    if (!F.os().has_error()) {
      F.keep();
      return;
    }
  }

private:
  PTACallGraph *callGraph;
  llvm::DenseSet<int> VisitedNodes;
  llvm::DenseSet<std::pair<int, int>> VisitedEdges;

  bool edgeVisited(PTACallGraphEdge *edge) {
    auto pair = std::make_pair(edge->getSrcID(), edge->getDstID());
    auto result = (VisitedEdges.find(pair) == VisitedEdges.end());
    if (result)
      VisitedEdges.insert(pair);
    return !result;
  }

  void dumpNode(raw_ostream &O, PTACallGraphNode *node) {
    O << "  node\n  [\n"
      << "    id Node" << node->getId() << "\n"
      << "    label \"" << node->getFunction()->getName() << "\"\n"
      << "  ]\n";
  }

  void dumpEdge(raw_ostream &O, PTACallGraphEdge *edge) {
    if (edgeVisited(edge)) return;

    O << "  edge\n  [\n"
      << "    source Node" << edge->getSrcID() << "\n"
      << "    target Node" << edge->getDstID() << "\n"
      << "    type " << (edge->isDirectCallEdge() ? "\"direct\"" : "\"indirect\"") << "\n";

    bool hasTailCall = false;
    auto directCalles = edge->getDirectCalls();
    for (auto *callBlockNode : directCalles) {
      auto callSite = cast<CallInst>(callBlockNode->getCallSite());
      if (callSite->isTailCall()) {
        hasTailCall = true;
        break;
      }
    }
    O << "    isTailCall " << (int)hasTailCall << "\n  ]\n";
  }

  PTACallGraph::FunctionSet getIndCallees(PTACallGraphNode *node) {
    for (PTACallGraph::CallEdgeMap::iterator
             it = callGraph->getIndCallMap().begin(),
             eit = callGraph->getIndCallMap().end();
         it != eit; ++it) {
      auto caller = it->first;
      if (caller->getFun() == node->getFunction()) {
        return it->second;
      }
    }
    return PTACallGraph::FunctionSet();
  }
};

class GMLICFGWriter {
public:
  GMLICFGWriter(ICFG *_icfg) : icfg(_icfg) {}

  void dumpToGML(std::string fileName) {
    std::error_code err;
    ToolOutputFile F(fileName.c_str(), err, llvm::sys::fs::F_None);
    if (err) {
      F.os().clear_error();
      return;
    }

    F.os() << "graph \n[\n";
    F.os() << "  directed 1\n";

    for (ICFG::iterator it = icfg->begin(), eit = icfg->end(); it != eit;
         ++it) {
      ICFGNode *node = it->second;

      // What about other Node types?
      if (SVFUtil::isa<IntraBlockNode>(node) ||
          SVFUtil::isa<FunEntryBlockNode>(node) ||
          SVFUtil::isa<FunExitBlockNode>(node) ||
          SVFUtil::isa<CallBlockNode>(node) || SVFUtil::isa<RetBlockNode>(node))
        dumpNode(F.os(), node);

      for (ICFGNode::iterator sit = node->OutEdgeBegin(),
                              esit = node->OutEdgeEnd();
           sit != esit; ++sit) {
        ICFGEdge *edge = *sit;
        if (edge->isCallCFGEdge()) {
          dumpEdge(F.os(), edge, "call");
        } else if (edge->isRetCFGEdge()) {
          dumpEdge(F.os(), edge, "return");
        } else if (edge->isIntraCFGEdge()) {
          dumpEdge(F.os(), edge, "intra");
        }
      }
    }
    F.os() << "]\n";

    F.os().close();
    if (!F.os().has_error()) {
      F.keep();
      return;
    }
  }

private:
  ICFG *icfg;

  void dumpNode(raw_ostream &O, ICFGNode *node) {
    SVF::NodeID id = node->getId();
    O << "  node\n  [\n"
      << "    id Node" << id << "\n"
      << "    label Node" << id << "\n"
      << "    func \"" << node->getFun()->getName() << "\"\n"
      << "    type \"" << getICFGKindString(node->getNodeKind()) << "\"\n";

    // Record if it is a tail call.
    if (auto *callNode = SVFUtil::dyn_cast<CallBlockNode>(node)) {
      auto *callInst = llvm::cast<CallInst>(callNode->getCallSite());
      O << "    isTailCall " << (int)callInst->isTailCall() << "\n";
      O << "    isIndirectCall " << (int)callNode->isIndirectCall() << "\n";
    }

    O << "  ]\n";
  }

  void dumpEdge(raw_ostream &O, ICFGEdge *edge, std::string type) {
    O << "  edge\n  [\n"
      << "    source Node" << edge->getSrcID() << "\n"
      << "    target Node" << edge->getDstID() << "\n"
      << "    type \"" << type << "\"\n"
      << "  ]\n";
  }

  std::string getICFGKindString(const int kind) {
    switch (kind) {
    case ICFGNode::IntraBlock:
      return "intra";
    case ICFGNode::FunEntryBlock:
      return "entry";
    case ICFGNode::FunExitBlock:
      return "exit";
    case ICFGNode::FunCallBlock:
      return "call";
    case ICFGNode::FunRetBlock:
      return "ret";
    default:
      return "";
    }
  }
};

/*!
 * An example to query alias results of two LLVM values
 */
AliasResult aliasQuery(PointerAnalysis *pta, Value *v1, Value *v2) {
  return pta->alias(v1, v2);
}

/*!
 * An example to print points-to set of an LLVM value
 */
std::string printPts(PointerAnalysis *pta, Value *val) {
  std::string str;
  raw_string_ostream rawstr(str);

  NodeID pNodeId = pta->getPAG()->getValueNode(val);
  const PointsTo &pts = pta->getPts(pNodeId);
  for (PointsTo::iterator ii = pts.begin(), ie = pts.end(); ii != ie; ii++) {
    rawstr << " " << *ii << " ";
    PAGNode *targetObj = pta->getPAG()->getPAGNode(*ii);
    if (targetObj->hasValue()) {
      rawstr << "(" << *targetObj->getValue() << ")\t ";
    }
  }

  return rawstr.str();
}

/*!
 * An example to query/collect all successor nodes from a ICFGNode (iNode) along
 * control-flow graph (ICFG)
 */
void traverseOnICFG(ICFG *icfg, const Instruction *inst) {
  ICFGNode *iNode = icfg->getBlockICFGNode(inst);
  FIFOWorkList<const ICFGNode *> worklist;
  std::set<const ICFGNode *> visited;
  worklist.push(iNode);

  /// Traverse along VFG
  while (!worklist.empty()) {
    const ICFGNode *vNode = worklist.pop();
    for (ICFGNode::const_iterator it = iNode->OutEdgeBegin(),
                                  eit = iNode->OutEdgeEnd();
         it != eit; ++it) {
      ICFGEdge *edge = *it;
      ICFGNode *succNode = edge->getDstNode();
      if (visited.find(succNode) == visited.end()) {
        visited.insert(succNode);
        worklist.push(succNode);

        if (succNode->getNodeKind() == ICFGNode::IntraBlock) {
        }
      }
    }
  }
}

bool traverseOnPAG(Value *val) {
  PAG *pag = PAG::getPAG();

  PAGNode *pNode = pag->getPAGNode(pag->getValueNode(val));
  FIFOWorkList<const PAGNode *> worklist;
  std::set<const PAGNode *> visited;
  worklist.push(pNode);

  /// Traverse along VFG
  while (!worklist.empty()) {
    const PAGNode *pNode = worklist.pop();
    for (PAGNode::const_iterator it = pNode->OutEdgeBegin(),
                                 eit = pNode->OutEdgeEnd();
         it != eit; ++it) {
      PAGEdge *edge = *it;
      if (edge->getEdgeKind() == PAGEdge::Call ||
          edge->getEdgeKind() == PAGEdge::Ret)
        return true;

      PAGNode *succNode = edge->getDstNode();
      if (visited.find(succNode) == visited.end()) {
        visited.insert(succNode);
        worklist.push(succNode);
      }
    }
  }
  return false;
}

/*!
 * An example to query/collect all the uses of a definition of a value along
 * value-flow graph (VFG)
 */
bool traverseOnVFG(const SVFG *vfg, Value *val) {
  PAG *pag = PAG::getPAG();

  PAGNode *pNode = pag->getPAGNode(pag->getValueNode(val));
  if (!vfg->hasDef(pNode))
    return false;

  const VFGNode *vNode = vfg->getDefSVFGNode(pNode);
  FIFOWorkList<const VFGNode *> worklist;
  std::set<const VFGNode *> visited;
  worklist.push(vNode);

  /// Traverse along VFG
  while (!worklist.empty()) {
    const VFGNode *vNode = worklist.pop();
    for (VFGNode::const_iterator it = vNode->OutEdgeBegin(),
                                 eit = vNode->OutEdgeEnd();
         it != eit; ++it) {
      VFGEdge *edge = *it;
      if (!edge->isIntraVFGEdge())
        return true;

      VFGNode *succNode = edge->getDstNode();
      if (visited.find(succNode) == visited.end()) {
        visited.insert(succNode);
        worklist.push(succNode);
      }
    }
  }
  return false;
}

void P(std::string &&log) { outs() << log << "\n"; }

const SVFFunction *findSVFFunctionInModule(SVFModule *module,
                                           std::string name) {
  for (auto *func : *module) {
    if (func->getName().equals(name.c_str()))
      return func;
  }
}

void findExternalValue(const SVFG *vfg, const SVFFunction *fun) {
  std::vector<Value *> externalValues;

  for (auto &BB : *fun->getLLVMFun()) {
    for (auto &I : BB) {
      bool isExternal = traverseOnPAG(&I);
      if (isExternal) {
        outs() << I << "\n";
        externalValues.push_back(&I);
      }

      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        Type *type = GEP->getSourceElementType();
        if (type->isStructTy())
          if (type->getStructName().startswith_lower("class")) {
            // We are GEPing a class.
            auto idxValue = GEP->getOperand(1);
            if (auto idxConstant = dyn_cast<ConstantInt>(idxValue)) {
              auto idx = idxConstant->getSExtValue();
            }
          }
      }
    }
  }
}

void dumpIndirectCallMap(PTACallGraph *callgraph, ICFG *icfg,
                         std::string fileName) {
  std::error_code err;
  ToolOutputFile F(fileName.c_str(), err, llvm::sys::fs::F_None);
  if (err) {
    F.os().clear_error();
    return;
  }

  PTACallGraph::CallEdgeMap::const_iterator iter =
      callgraph->getIndCallMap().begin();
  PTACallGraph::CallEdgeMap::const_iterator eiter =
      callgraph->getIndCallMap().end();

  for (; iter != eiter; iter++) {
    const CallBlockNode *callBlock = iter->first;
    const PTACallGraph::FunctionSet &functions = iter->second;
    const Instruction *cs = callBlock->getCallSite();
    assert(callBlock->isIndirectCall() && "this is not an indirect call?");

    for (PTACallGraph::FunctionSet::const_iterator func_iter =
             functions.begin();
         func_iter != functions.end(); func_iter++) {
      const SVFFunction *callee = *func_iter;

      CallBlockNode *callerBlockNode = icfg->getCallBlockNode(cs);
      FunEntryBlockNode *calleeEntryNode = icfg->getFunEntryBlockNode(callee);

      F.os() << "Node" << callerBlockNode->getId();
      F.os() << " " << callee->getName() << "\n";
    }
  }

  F.os().close();
  if (!F.os().has_error()) {
    F.keep();
    return;
  }
}

int main(int argc, char *argv[]) {
  int arg_num = 0;
  char **arg_value = new char *[argc];
  std::vector<std::string> moduleNameVec;
  SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
  cl::ParseCommandLineOptions(arg_num, arg_value,
                              "Whole Program Points-to Analysis\n");

  SVFModule *svfModule =
      LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

  PAGBuilder builder;
  P("Program starts.");
  PAG *pag = builder.build(svfModule);
  ICFG *icfg = pag->getICFG();
  P("PAG and ICFG complete.");

  /// Create Andersen's pointer analysis
  // FlowSensitive *pta = FlowSensitive::createFSWPA(pag);
  // AndersenWaveDiff *pta = new AndersenWaveDiff(pag);
  TypeAnalysis *pta = new TypeAnalysis(pag);
  pta->disablePrintStat();
  pta->analyze();
  // pta->writeToFile("pta.txt");
  P("WPA complete.");
  // Get call graph
  PTACallGraph *callgraph = pta->getPTACallGraph();
  GMLCallGraphWriter writer(callgraph);
  writer.dumpToGML("callgraph.gml");
  icfg->updateCallGraph(callgraph);
  GMLICFGWriter icfgWriter(icfg);
  // icfgWriter.dumpToGML("icfg.gml");
  // dumpIndirectCallMap(callgraph, icfg, "icallmap.txt");

  // Value-Flow Graph (VFG)
  VFG *vfg = new VFG(callgraph);
  P("VFG complete.");

  // Sparse Value-Flow Graph (SVFG)
  SVFGBuilder svfBuilder;
  SVFG *svfg = svfBuilder.buildFullSVFGWithoutOPT(pta);
  P("SVFG complete.");
}
