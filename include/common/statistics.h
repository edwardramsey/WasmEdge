// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

//===-- wasmedge/common/statistics.h - Executor statistics definition -----===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the statistics class of runtime.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "common/configure.h"
#include "common/enum_ast.hpp"
#include "common/errcode.h"
#include "common/log.h"
#include "common/span.h"
#include "common/timer.h"

#include <atomic>
#include <vector>

namespace WasmEdge {
namespace Statistics {

class StatisticsDetails {
  // Registers，Memory，Flow Control，32-bit Integer operators，64-bit Integer operators，other
public:
  std::atomic_uint64_t InstrCntReg;
  std::atomic_uint64_t InstrCntMem;
  std::atomic_uint64_t InstrCntControl;
  std::atomic_uint64_t InstrCnt32IntOp;
  std::atomic_uint64_t InstrCnt64IntOp;
  std::atomic_uint64_t InstrCntOther;

  StatisticsDetails()
  : InstrCntReg(0), InstrCntMem(0), InstrCntControl(0),
        InstrCnt32IntOp(0), InstrCnt64IntOp(0), InstrCntOther(0) {

  }

};

class Statistics {
public:
  Statistics(const uint64_t Lim = UINT64_MAX)
      : CostTab(UINT16_MAX + 1, 1ULL), InstrCnt(0), CostLimit(Lim), CostSum(0), InsStatisticsDetails() {
  }
  Statistics(Span<const uint64_t> Tab, const uint64_t Lim = UINT64_MAX)
      : CostTab(Tab.begin(), Tab.end()), InstrCnt(0), CostLimit(Lim),
        CostSum(0), InsStatisticsDetails() {
    if (CostTab.size() < UINT16_MAX + 1) {
      CostTab.resize(UINT16_MAX + 1, 0ULL);
    }
  }
  ~Statistics() = default;

  /// Increment of instruction counter.
  void incInstrCount() { InstrCnt.fetch_add(1, std::memory_order_relaxed); }

  /// Getter of instruction counter.
  uint64_t getInstrCount() const {
    return InstrCnt.load(std::memory_order_relaxed);
  }
  std::atomic_uint64_t &getInstrCountRef() { return InstrCnt; }

  /// Getter of instruction per second.
  double getInstrPerSecond() const {
    return static_cast<double>(InstrCnt) /
           std::chrono::duration<double>(getWasmExecTime()).count();
  }

  /// Setter and setter of cost table.
  void setCostTable(Span<const uint64_t> NewTable) {
    CostTab.assign(NewTable.begin(), NewTable.end());
    if (unlikely(CostTab.size() < UINT16_MAX + 1)) {
      CostTab.resize(UINT16_MAX + 1, 0ULL);
    }
  }
  Span<const uint64_t> getCostTable() const noexcept { return CostTab; }
  Span<uint64_t> getCostTable() noexcept { return CostTab; }

  std::atomic_uint64_t &getInstrCntRegRef() { return InsStatisticsDetails.InstrCntReg; }
  std::atomic_uint64_t &getInstrCntMemRef() { return InsStatisticsDetails.InstrCntMem; }
  std::atomic_uint64_t &getInstrCntControlRef() { return InsStatisticsDetails.InstrCntControl; }
  std::atomic_uint64_t &getInstrCnt32IntOpRef() { return InsStatisticsDetails.InstrCnt32IntOp; }
  std::atomic_uint64_t &getInstrCnt64IntOpRef() { return InsStatisticsDetails.InstrCnt64IntOp; }
  std::atomic_uint64_t &getInstrCntOtherRef() { return InsStatisticsDetails.InstrCntOther; }

  /// Adder of instruction costs.
  bool addInstrCost(OpCode Code) {
    addInsDetails(Code);
    return addCost(CostTab[uint16_t(Code)]);
  }

  void addInsDetails(const OpCode& Code) {
    switch (Code) {
    case OpCode::Local__get:
    case OpCode::Local__set:
    case OpCode::Local__tee:
    case OpCode::Global__get:
    case OpCode::Global__set:
      InsStatisticsDetails.InstrCntReg.fetch_add(1, std::memory_order_relaxed);
      break;
    case OpCode::I32__load:
    case OpCode::I64__load:
    case OpCode::F32__load:
    case OpCode::F64__load:
    case OpCode::I32__load8_s:
    case OpCode::I32__load8_u:
    case OpCode::I32__load16_s:
    case OpCode::I32__load16_u:
    case OpCode::I64__load8_s:
    case OpCode::I64__load8_u:
    case OpCode::I64__load16_s:
    case OpCode::I64__load16_u:
    case OpCode::I64__load32_s:
    case OpCode::I64__load32_u:
    case OpCode::I32__store:
    case OpCode::I64__store:
    case OpCode::F32__store:
    case OpCode::F64__store:
    case OpCode::I32__store8:
    case OpCode::I32__store16:
    case OpCode::I64__store8:
    case OpCode::I64__store16:
    case OpCode::I64__store32:
    case OpCode::Memory__size:
    case OpCode::Memory__grow:
      InsStatisticsDetails.InstrCntMem.fetch_add(1, std::memory_order_relaxed);
      break;
    case OpCode::Unreachable:
    case OpCode::Nop:
    case OpCode::Block:
    case OpCode::Loop:
    case OpCode::If:
    case OpCode::Else:
    case OpCode::End:
    case OpCode::Br:
    case OpCode::Br_if:
    case OpCode::Br_table:
    case OpCode::Return:
    case OpCode::Call:
    case OpCode::Call_indirect:
    case OpCode::Return_call:
    case OpCode::Return_call_indirect:
    case OpCode::Call_ref:
    case OpCode::Return_call_ref:
      InsStatisticsDetails.InstrCntControl.fetch_add(1, std::memory_order_relaxed);
      break;
    case OpCode::I32__eqz:
    case OpCode::I32__eq:
    case OpCode::I32__ne:
    case OpCode::I32__lt_s:
    case OpCode::I32__lt_u:
    case OpCode::I32__gt_s:
    case OpCode::I32__gt_u:
    case OpCode::I32__le_s:
    case OpCode::I32__le_u:
    case OpCode::I32__ge_s:
    case OpCode::I32__ge_u:
    case OpCode::F32__eq:
    case OpCode::F32__ne:
    case OpCode::F32__lt:
    case OpCode::F32__gt:
    case OpCode::F32__le:
    case OpCode::F32__ge:
    case OpCode::I32__clz:
    case OpCode::I32__ctz:
    case OpCode::I32__popcnt:
    case OpCode::I32__add:
    case OpCode::I32__sub:
    case OpCode::I32__mul:
    case OpCode::I32__div_s:
    case OpCode::I32__div_u:
    case OpCode::I32__rem_s:
    case OpCode::I32__rem_u:
    case OpCode::I32__and:
    case OpCode::I32__or:
    case OpCode::I32__xor:
    case OpCode::I32__shl:
    case OpCode::I32__shr_s:
    case OpCode::I32__shr_u:
    case OpCode::I32__rotl:
    case OpCode::I32__rotr:
    case OpCode::F32__abs:
    case OpCode::F32__neg:
    case OpCode::F32__ceil:
    case OpCode::F32__floor:
    case OpCode::F32__trunc:
    case OpCode::F32__nearest:
    case OpCode::F32__sqrt:
    case OpCode::F32__add:
    case OpCode::F32__sub:
    case OpCode::F32__mul:
    case OpCode::F32__div:
    case OpCode::F32__min:
    case OpCode::F32__max:
    case OpCode::F32__copysign:
    case OpCode::I32__wrap_i64:
    case OpCode::I32__trunc_f32_s:
    case OpCode::I32__trunc_f32_u:
    case OpCode::I32__trunc_f64_s:
    case OpCode::I32__trunc_f64_u:
    case OpCode::F32__convert_i32_s:
    case OpCode::F32__convert_i32_u:
    case OpCode::F32__convert_i64_s:
    case OpCode::F32__convert_i64_u:
    case OpCode::F32__demote_f64:
    case OpCode::I32__reinterpret_f32:
    case OpCode::F32__reinterpret_i32:
    case OpCode::I32__extend8_s:
    case OpCode::I32__extend16_s:
    case OpCode::I32__trunc_sat_f32_s:
    case OpCode::I32__trunc_sat_f32_u:
    case OpCode::I32__trunc_sat_f64_s:
    case OpCode::I32__trunc_sat_f64_u:
    case OpCode::I32__atomic__load:
    case OpCode::I32__atomic__load8_u:
    case OpCode::I32__atomic__load16_u:
    case OpCode::I32__atomic__store:
    case OpCode::I32__atomic__store8:
    case OpCode::I32__atomic__store16:
    case OpCode::I32__atomic__rmw__add:
    case OpCode::I32__atomic__rmw8__add_u:
    case OpCode::I32__atomic__rmw16__add_u:
    case OpCode::I32__atomic__rmw__sub:
    case OpCode::I32__atomic__rmw8__sub_u:
    case OpCode::I32__atomic__rmw16__sub_u:
    case OpCode::I32__atomic__rmw__and:
    case OpCode::I32__atomic__rmw8__and_u:
    case OpCode::I32__atomic__rmw16__and_u:
    case OpCode::I32__atomic__rmw__or:
    case OpCode::I32__atomic__rmw8__or_u:
    case OpCode::I32__atomic__rmw16__or_u:
    case OpCode::I32__atomic__rmw__xor:
    case OpCode::I32__atomic__rmw8__xor_u:
    case OpCode::I32__atomic__rmw16__xor_u:
    case OpCode::I32__atomic__rmw__xchg:
    case OpCode::I32__atomic__rmw8__xchg_u:
    case OpCode::I32__atomic__rmw16__xchg_u:
    case OpCode::I32__atomic__rmw__cmpxchg:
    case OpCode::I32__atomic__rmw8__cmpxchg_u:
    case OpCode::I32__atomic__rmw16__cmpxchg_u:
      InsStatisticsDetails.InstrCnt32IntOp.fetch_add(1, std::memory_order_relaxed);
      break;
    case OpCode::I64__eqz:
    case OpCode::I64__eq:
    case OpCode::I64__ne:
    case OpCode::I64__lt_s:
    case OpCode::I64__lt_u:
    case OpCode::I64__gt_s:
    case OpCode::I64__gt_u:
    case OpCode::I64__le_s:
    case OpCode::I64__le_u:
    case OpCode::I64__ge_s:
    case OpCode::I64__ge_u:
    case OpCode::F64__eq:
    case OpCode::F64__ne:
    case OpCode::F64__lt:
    case OpCode::F64__gt:
    case OpCode::F64__le:
    case OpCode::F64__ge:
    case OpCode::I64__clz:
    case OpCode::I64__ctz:
    case OpCode::I64__popcnt:
    case OpCode::I64__add:
    case OpCode::I64__sub:
    case OpCode::I64__mul:
    case OpCode::I64__div_s:
    case OpCode::I64__div_u:
    case OpCode::I64__rem_s:
    case OpCode::I64__rem_u:
    case OpCode::I64__and:
    case OpCode::I64__or:
    case OpCode::I64__xor:
    case OpCode::I64__shl:
    case OpCode::I64__shr_s:
    case OpCode::I64__shr_u:
    case OpCode::I64__rotl:
    case OpCode::I64__rotr:
    case OpCode::F64__abs:
    case OpCode::F64__neg:
    case OpCode::F64__ceil:
    case OpCode::F64__floor:
    case OpCode::F64__trunc:
    case OpCode::F64__nearest:
    case OpCode::F64__sqrt:
    case OpCode::F64__add:
    case OpCode::F64__sub:
    case OpCode::F64__mul:
    case OpCode::F64__div:
    case OpCode::F64__min:
    case OpCode::F64__max:
    case OpCode::F64__copysign:
    case OpCode::I64__extend_i32_s:
    case OpCode::I64__extend_i32_u:
    case OpCode::I64__trunc_f32_s:
    case OpCode::I64__trunc_f32_u:
    case OpCode::I64__trunc_f64_s:
    case OpCode::I64__trunc_f64_u:
    case OpCode::F64__convert_i32_s:
    case OpCode::F64__convert_i32_u:
    case OpCode::F64__convert_i64_s:
    case OpCode::F64__convert_i64_u:
    case OpCode::F64__promote_f32:
    case OpCode::I64__reinterpret_f64:
    case OpCode::F64__reinterpret_i64:
    case OpCode::I64__extend8_s:
    case OpCode::I64__extend16_s:
    case OpCode::I64__extend32_s:
    case OpCode::I64__trunc_sat_f32_s:
    case OpCode::I64__trunc_sat_f32_u:
    case OpCode::I64__trunc_sat_f64_s:
    case OpCode::I64__trunc_sat_f64_u:
    case OpCode::I64__atomic__load:
    case OpCode::I64__atomic__load8_u:
    case OpCode::I64__atomic__load16_u:
    case OpCode::I64__atomic__load32_u:
    case OpCode::I64__atomic__store:
    case OpCode::I64__atomic__store8:
    case OpCode::I64__atomic__store16:
    case OpCode::I64__atomic__store32:
    case OpCode::I64__atomic__rmw__add:
    case OpCode::I64__atomic__rmw8__add_u:
    case OpCode::I64__atomic__rmw16__add_u:
    case OpCode::I64__atomic__rmw32__add_u:
    case OpCode::I64__atomic__rmw__sub:
    case OpCode::I64__atomic__rmw8__sub_u:
    case OpCode::I64__atomic__rmw16__sub_u:
    case OpCode::I64__atomic__rmw32__sub_u:
    case OpCode::I64__atomic__rmw__and:
    case OpCode::I64__atomic__rmw8__and_u:
    case OpCode::I64__atomic__rmw16__and_u:
    case OpCode::I64__atomic__rmw32__and_u:
    case OpCode::I64__atomic__rmw__or:
    case OpCode::I64__atomic__rmw8__or_u:
    case OpCode::I64__atomic__rmw16__or_u:
    case OpCode::I64__atomic__rmw32__or_u:
    case OpCode::I64__atomic__rmw__xor:
    case OpCode::I64__atomic__rmw8__xor_u:
    case OpCode::I64__atomic__rmw16__xor_u:
    case OpCode::I64__atomic__rmw32__xor_u:
    case OpCode::I64__atomic__rmw__xchg:
    case OpCode::I64__atomic__rmw8__xchg_u:
    case OpCode::I64__atomic__rmw16__xchg_u:
    case OpCode::I64__atomic__rmw32__xchg_u:
    case OpCode::I64__atomic__rmw__cmpxchg:
    case OpCode::I64__atomic__rmw8__cmpxchg_u:
    case OpCode::I64__atomic__rmw16__cmpxchg_u:
    case OpCode::I64__atomic__rmw32__cmpxchg_u:
      InsStatisticsDetails.InstrCnt64IntOp.fetch_add(1, std::memory_order_relaxed);
      break;
    default:
      InsStatisticsDetails.InstrCntOther.fetch_add(1, std::memory_order_relaxed);
      break;
    }
  }

  std::string getInsDetails() const {
    return "Register: " + std::to_string(InsStatisticsDetails.InstrCntReg.load(std::memory_order_relaxed)) + ", "
           + "FlowControl: " + std::to_string(InsStatisticsDetails.InstrCntControl.load(std::memory_order_relaxed)) + ", "
          + "Memory: "  + std::to_string(InsStatisticsDetails.InstrCntMem.load(std::memory_order_relaxed)) + ", "
          + "32BitOperators: " + std::to_string(InsStatisticsDetails.InstrCnt32IntOp.load(std::memory_order_relaxed)) + ", "
           + "64BitOperators: " + std::to_string(InsStatisticsDetails.InstrCnt64IntOp.load(std::memory_order_relaxed)) + ", "
           + "Others: " + std::to_string(InsStatisticsDetails.InstrCntOther.load(std::memory_order_relaxed));

  }

  /// Subber of instruction costs.
  bool subInstrCost(OpCode Code) { return subCost(CostTab[uint16_t(Code)]); }

  /// Getter of total gas cost.
  uint64_t getTotalCost() const {
    return CostSum.load(std::memory_order_relaxed);
  }
  std::atomic_uint64_t &getTotalCostRef() { return CostSum; }

  /// Getter and setter of cost limit.
  void setCostLimit(uint64_t Lim) { CostLimit = Lim; }
  uint64_t getCostLimit() const { return CostLimit; }

  /// Add cost and return false if exceeded limit.
  bool addCost(uint64_t Cost) {
    const auto Limit = CostLimit;
    uint64_t OldCostSum = CostSum.load(std::memory_order_relaxed);
    uint64_t NewCostSum;
    do {
      NewCostSum = OldCostSum + Cost;
      if (unlikely(NewCostSum > Limit)) {
        spdlog::error("Cost exceeded limit. Force terminate the execution.");
        return false;
      }
    } while (!CostSum.compare_exchange_weak(OldCostSum, NewCostSum,
                                            std::memory_order_relaxed));
    return true;
  }

  /// Return cost back.
  bool subCost(uint64_t Cost) {
    uint64_t OldCostSum = CostSum.load(std::memory_order_relaxed);
    uint64_t NewCostSum;
    do {
      if (unlikely(OldCostSum <= Cost)) {
        return false;
      }
      NewCostSum = OldCostSum - Cost;
    } while (!CostSum.compare_exchange_weak(OldCostSum, NewCostSum,
                                            std::memory_order_relaxed));
    return true;
  }

  /// Clear measurement data for instructions.
  void clear() noexcept {
    TimeRecorder.reset();
    InstrCnt.store(0, std::memory_order_relaxed);
    CostSum.store(0, std::memory_order_relaxed);
  }

  /// Start recording wasm time.
  void startRecordWasm() noexcept {
    TimeRecorder.startRecord(Timer::TimerTag::Wasm);
  }

  /// Stop recording wasm time.
  void stopRecordWasm() noexcept {
    TimeRecorder.stopRecord(Timer::TimerTag::Wasm);
  }

  /// Start recording host function time.
  void startRecordHost() noexcept {
    TimeRecorder.startRecord(Timer::TimerTag::HostFunc);
  }

  /// Stop recording host function time.
  void stopRecordHost() noexcept {
    TimeRecorder.stopRecord(Timer::TimerTag::HostFunc);
  }

  /// Getter of execution time.
  Timer::Timer::Clock::duration getWasmExecTime() const noexcept {
    return TimeRecorder.getRecord(Timer::TimerTag::Wasm);
  }
  Timer::Timer::Clock::duration getHostFuncExecTime() const noexcept {
    return TimeRecorder.getRecord(Timer::TimerTag::HostFunc);
  }
  Timer::Timer::Clock::duration getTotalExecTime() const noexcept {
    return TimeRecorder.getRecord(Timer::TimerTag::Wasm) +
           TimeRecorder.getRecord(Timer::TimerTag::HostFunc);
  }

  void dumpToLog(const Configure &Conf) const noexcept {
    auto Nano = [](auto &&Duration) {
      return std::chrono::nanoseconds(Duration).count();
    };
    const auto &StatConf = Conf.getStatisticsConfigure();
    if (StatConf.isTimeMeasuring() || StatConf.isInstructionCounting() ||
        StatConf.isCostMeasuring()) {
      spdlog::info("====================  Statistics  ====================");
    }
    if (StatConf.isTimeMeasuring()) {
      spdlog::info(" Total execution time: {} ns", Nano(getTotalExecTime()));
      spdlog::info(" Wasm instructions execution time: {} ns",
                   Nano(getWasmExecTime()));
      spdlog::info(" Host functions execution time: {} ns",
                   Nano(getHostFuncExecTime()));
    }
    if (StatConf.isInstructionCounting()) {
      spdlog::info(" Executed wasm instructions count: {}", getInstrCount());
    }
    if (StatConf.isCostMeasuring()) {
      spdlog::info(" Gas costs: {}", getTotalCost());
    }
    if (StatConf.isInstructionCounting() && StatConf.isTimeMeasuring()) {
      spdlog::info(" Instructions per second: {}",
                   static_cast<uint64_t>(getInstrPerSecond()));
    }
    if(StatConf.isInstructionCounting()) {
      spdlog::info(" Instructions details: {}", getInsDetails().c_str());
    }
    if (StatConf.isTimeMeasuring() || StatConf.isInstructionCounting() ||
        StatConf.isCostMeasuring()) {
      spdlog::info("=======================   End   ======================");
    }
  }

private:
  std::vector<uint64_t> CostTab;
  std::atomic_uint64_t InstrCnt;
  uint64_t CostLimit;
  std::atomic_uint64_t CostSum;
  Timer::Timer TimeRecorder;
  StatisticsDetails InsStatisticsDetails;
};

} // namespace Statistics
} // namespace WasmEdge
