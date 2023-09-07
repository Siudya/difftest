/***************************************************************************************
* Copyright (c) 2020-2021 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
*
* XiangShan is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*          http://license.coscl.org.cn/MulanPSL2
*
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
*
* See the Mulan PSL v2 for more details.
***************************************************************************************/

#ifndef __NEMU_PROXY_H
#define __NEMU_PROXY_H

#include <unistd.h>
#include <dlfcn.h>
#include <cstddef>

#include "common.h"

class RefProxy {
public:
  // public callable functions
  void (*memcpy)(paddr_t nemu_addr, void *dut_buf, size_t n, bool direction) = NULL;
  void (*regcpy)(void *dut, bool direction) = NULL;
  void (*csrcpy)(void *dut, bool direction) = NULL;
  void (*uarchstatus_cpy)(void *dut, bool direction) = NULL;
  int (*store_commit)(uint64_t *saddr, uint64_t *sdata, uint8_t *smask) = NULL;
  void (*exec)(uint64_t n) = NULL;
  vaddr_t (*guided_exec)(void *disambiguate_para) = NULL;
  void (*update_config)(void *config) = NULL;
  void (*raise_intr)(uint64_t no) = NULL;
  void (*isa_reg_display)() = NULL;
  void (*query)(void *result_buffer, uint64_t type) = NULL;
  void (*debug_mem_sync)(paddr_t addr, void *bytes, size_t size) = NULL;
  void (*load_flash_bin)(void *flash_bin, size_t size) = NULL;
};
extern const char *difftest_ref_so;

#define NEMU_ENV_VARIABLE "NEMU_HOME"
#define NEMU_SO_FILENAME  "build/riscv64-nemu-interpreter-so"
class NemuProxy : public RefProxy {
public:
  NemuProxy(int coreid);
private:
};

#define SPIKE_ENV_VARIABLE "SPIKE_HOME"
#define SPIKE_SO_FILENAME  "difftest/build/riscv64-spike-so"

// To proxy only interacts with one spike .so library even for multicore,
// use static member function to hook interface functions (with coreid) in Spike.
//
// To make this changes transparent for use proxy objects in Difftest,
// SpikeProxy replaces function pointers in Refproxy to member functions.
// These member functions invoke corresponding static ones with its own `coreid`.
//
// Note: std::bind cannot be used to create partial function with specific `coreid`
// and assigned to normal function pointers.
class SpikeProxy {
public:
  SpikeProxy(int coreid): coreid(coreid)
  {
    // initialize member functions independent to `coreid`
    debug_mem_sync = sim_debug_mem_sync;
    load_flash_bin = sim_load_flash_bin;
  };
  static void spike_init();
  void memcpy(paddr_t nemu_addr, void *dut_buf, size_t n, bool direction);
  void regcpy(void *dut, bool direction);
  void csrcpy(void *dut, bool direction);
  void uarchstatus_cpy(void *dut, bool direction);
  int store_commit(uint64_t *saddr, uint64_t *sdata, uint8_t *smask);
  void exec(uint64_t n);
  vaddr_t guided_exec(void *disambiguate_para);
  void update_config(void *config);
  void raise_intr(uint64_t no);
  void isa_reg_display();
  void query(void *result_buffer, uint64_t type);
  void (*debug_mem_sync)(paddr_t addr, void *bytes, size_t size) = nullptr;
  void (*load_flash_bin)(void *flash_bin, size_t size) = nullptr;
private:
  size_t coreid;
  static void* handle;
  static void (*sim_memcpy)(size_t coreid, paddr_t nemu_addr, void *dut_buf, size_t n, bool direction);
  static void (*sim_regcpy)(size_t coreid, void *dut, bool direction);
  static void (*sim_csrcpy)(size_t coreid, void *dut, bool direction);
  static void (*sim_uarchstatus_cpy)(size_t coreid, void *dut, bool direction);
  static int (*sim_store_commit)(size_t coreid, uint64_t *saddr, uint64_t *sdata, uint8_t *smask);
  static void (*sim_exec)(size_t coreid, uint64_t n);
  static vaddr_t (*sim_guided_exec)(size_t coreid, void *disambiguate_para);
  static void (*sim_update_config)(size_t coreid, void *config);
  static void (*sim_raise_intr)(size_t coreid, uint64_t no);
  static void (*sim_isa_reg_display)(size_t coreid);
  static void (*sim_query)(size_t coreid, void *result_buffer, uint64_t type);
  static void (*sim_debug_mem_sync)(paddr_t addr, void *bytes, size_t size);
  static void (*sim_load_flash_bin)(void *flash_bin, size_t size);
 };

struct SyncState {
  uint64_t lrscValid;
  uint64_t lrscAddr;
};

struct ExecutionGuide {
  // force raise exception
  bool force_raise_exception;
  uint64_t exception_num;
  uint64_t mtval;
  uint64_t stval;
  // force set jump target
  bool force_set_jump_target;
  uint64_t jump_target;
};

typedef struct DynamicConfig {
  bool ignore_illegal_mem_access = false;
  bool debug_difftest = false;
} DynamicSimulatorConfig;

void ref_misc_put_gmaddr(uint8_t* ptr);

#endif