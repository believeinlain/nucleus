#include <stdio.h>
#include <vector>
#include <nlohmann/json.hpp>

#include "bb.h"
#include "insn.h"


void
BB::print(FILE *out)
{
  fprintf(out, "BB @0x%016jx (score %.10f) %s%s%s%s {\n", 
          start, score, invalid ? "i" : "-", privileged ? "p" : "-", 
          addrtaken ? "a" : "-", padding ? "n" : "-");
  if(invalid) {
    fprintf(out, "  0x%016jx  (bad)", start);
  } else {
    for(auto &ins: insns) {
      ins.print(out);
    }
  }
  if(!ancestors.empty()) {
    fprintf(out, "--A ancestors:\n");
    for(auto &e: ancestors) {
      fprintf(out, "--A 0x%016jx (%s)\n", e.src->insns.back().start, e.type2str().c_str());
    }
  }
  if(!targets.empty()) {
    fprintf(out, "--T targets:\n");
    for(auto &e: targets) {
      fprintf(out, "--T 0x%016jx (%s)\n", e.dst->start+e.offset, e.type2str().c_str());
    }
  }
  fprintf(out, "}\n\n");
}

void
BB::serialize(FILE *out)
{
  using json = nlohmann::json;
  json j;
  j["address"] = start;
  std::vector<uint64_t> target_addr;
  std::vector<uint64_t> ancestor_addr;
  if(!ancestors.empty()) {
    for(auto &e: ancestors) {
	  ancestor_addr.push_back(e.src->insns.back().start);
    }
  }
  if(!targets.empty()) {
    for(auto &e: targets) {
	  target_addr.push_back(e.dst->start+e.offset);
    }
  }
  j["ancestors"] = ancestor_addr;
  j["targets"] = target_addr;
  fprintf(out, "%s\n", j.dump().c_str());
}


bool
BB::is_called()
{
  for(auto &e: ancestors) {
    if((e.type == Edge::EDGE_TYPE_CALL) 
       || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)) {
      return true;
    }
  }

  return false;
}


bool
BB::returns()
{
  return (insns.back().flags & Instruction::INS_FLAG_RET);
}

