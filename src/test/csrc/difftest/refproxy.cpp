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

#include "refproxy.h"
#include <unistd.h>
#include <dlfcn.h>
#include <cstddef>

// Initialize global and static variables
uint8_t* goldenMem = NULL;
const char *difftest_ref_so = NULL;

void* SpikeProxy::handle = nullptr;
void (*SpikeProxy::sim_memcpy)(size_t coreid, paddr_t nemu_addr, void *dut_buf, size_t n, bool direction) = nullptr;
void (*SpikeProxy::sim_regcpy)(size_t coreid, void *dut, bool direction) = nullptr;
void (*SpikeProxy::sim_csrcpy)(size_t coreid, void *dut, bool direction) = nullptr;
void (*SpikeProxy::sim_uarchstatus_cpy)(size_t coreid, void *dut, bool direction) = nullptr;
int (*SpikeProxy::sim_store_commit)(size_t coreid, uint64_t *saddr, uint64_t *sdata, uint8_t *smask) = nullptr;
void (*SpikeProxy::sim_exec)(size_t coreid, uint64_t n) = nullptr;
vaddr_t (*SpikeProxy::sim_guided_exec)(size_t coreid, void *disambiguate_para) = nullptr;
void (*SpikeProxy::sim_update_config)(size_t coreid, void *config) = nullptr;
void (*SpikeProxy::sim_raise_intr)(size_t coreid, uint64_t no) = nullptr;
void (*SpikeProxy::sim_isa_reg_display)(size_t coreid) = nullptr;
void (*SpikeProxy::sim_query)(size_t coreid, void *result_buffer, uint64_t type) = nullptr;
void (*SpikeProxy::sim_debug_mem_sync)(paddr_t addr, void *bytes, size_t size) = nullptr;
void (*SpikeProxy::sim_load_flash_bin)(void *flash_bin, size_t size) = nullptr;

#define check_and_assert(func)                                \
  do {                                                        \
    if (!func) {                                              \
      printf("ERROR: %s\n", dlerror());  \
      assert(func);                                           \
    }                                                         \
  } while (0);

NemuProxy::NemuProxy(int coreid) {
  if (difftest_ref_so == NULL) {
    printf("--diff is not given, "
        "try to use $(" NEMU_ENV_VARIABLE ")/" NEMU_SO_FILENAME " by default\n");
    const char *nemu_home = getenv(NEMU_ENV_VARIABLE);
    if (nemu_home == NULL) {
      printf("FATAL: $(" NEMU_ENV_VARIABLE ") is not defined!\n");
      exit(1);
    }
    const char *so = "/" NEMU_SO_FILENAME;
    char *buf = (char *)malloc(strlen(nemu_home) + strlen(so) + 1);
    strcpy(buf, nemu_home);
    strcat(buf, so);
    difftest_ref_so = buf;
  }

  printf("NemuProxy using %s\n", difftest_ref_so);

  void *handle = dlmopen(LM_ID_NEWLM, difftest_ref_so, RTLD_LAZY | RTLD_DEEPBIND);
  if(!handle){
    printf("%s\n", dlerror());
    assert(0);
  }

  this->memcpy = (void (*)(paddr_t, void *, size_t, bool))dlsym(handle, "difftest_memcpy");
  check_and_assert(this->memcpy);

  regcpy = (void (*)(void *, bool))dlsym(handle, "difftest_regcpy");
  check_and_assert(regcpy);

  csrcpy = (void (*)(void *, bool))dlsym(handle, "difftest_csrcpy");
  check_and_assert(csrcpy);

  uarchstatus_cpy = (void (*)(void *, bool))dlsym(handle, "difftest_uarchstatus_cpy");
  check_and_assert(uarchstatus_cpy);

  exec = (void (*)(uint64_t))dlsym(handle, "difftest_exec");
  check_and_assert(exec);

  guided_exec = (vaddr_t (*)(void *))dlsym(handle, "difftest_guided_exec");
  check_and_assert(guided_exec);

  update_config = (void (*)(void *))dlsym(handle, "update_dynamic_config");
  check_and_assert(update_config);

  store_commit = (int (*)(uint64_t*, uint64_t*, uint8_t*))dlsym(handle, "difftest_store_commit");
  check_and_assert(store_commit);

  raise_intr = (void (*)(uint64_t))dlsym(handle, "difftest_raise_intr");
  check_and_assert(raise_intr);

  isa_reg_display = (void (*)(void))dlsym(handle, "isa_reg_display");
  check_and_assert(isa_reg_display);

  load_flash_bin = (void (*)(void *flash_bin, size_t size))dlsym(handle, "difftest_load_flash");
  check_and_assert(load_flash_bin);

  query = (void (*)(void*, uint64_t))dlsym(handle, "difftest_query_ref");
#ifdef ENABLE_RUNHEAD
  check_and_assert(query);
#endif

  auto nemu_difftest_set_mhartid = (void (*)(int))dlsym(handle, "difftest_set_mhartid");
  if (NUM_CORES > 1) {
    check_and_assert(nemu_difftest_set_mhartid);
    nemu_difftest_set_mhartid(coreid);
  }

  auto nemu_misc_put_gmaddr = (void (*)(void*))dlsym(handle, "difftest_put_gmaddr");
  if (NUM_CORES > 1) {
    check_and_assert(nemu_misc_put_gmaddr);
    assert(goldenMem);
    nemu_misc_put_gmaddr(goldenMem);
  }

  auto nemu_init = (void (*)(void))dlsym(handle, "difftest_init");
  check_and_assert(nemu_init);

  nemu_init();
}

void ref_misc_put_gmaddr(uint8_t* ptr) {
  goldenMem = ptr;
}

void SpikeProxy::spike_init() 
{
  if (difftest_ref_so == NULL) {
    printf("--diff is not given, "
           "try to use $(" SPIKE_ENV_VARIABLE ")/" SPIKE_SO_FILENAME
           " by default\n");
    const char *spike_home = getenv(SPIKE_ENV_VARIABLE);
    if (spike_home == NULL) {
      printf("FATAL: $(" SPIKE_ENV_VARIABLE ") is not defined!\n");
      exit(1);
    }
    const char *so = "/" SPIKE_SO_FILENAME;
    char *buf = (char *)malloc(strlen(spike_home) + strlen(so) + 1);
    strcpy(buf, spike_home);
    strcat(buf, so);
    difftest_ref_so = buf;
  }

  printf("SpikeProxy using %s\n", difftest_ref_so);

  handle = dlmopen(LM_ID_NEWLM, difftest_ref_so, RTLD_LAZY | RTLD_DEEPBIND);
  if (!handle) {
    printf("%s\n", dlerror());
    assert(0);
  }

  auto sim_init = (void (*)())dlsym(handle, "difftest_init");
  check_and_assert(sim_init);

  sim_memcpy = (void (*)(size_t, paddr_t, void *, size_t, bool))dlsym(handle, "difftest_memcpy");
  check_and_assert(sim_memcpy);

  sim_regcpy = (void (*)(size_t, void *, bool))dlsym(handle, "difftest_regcpy");
  check_and_assert(sim_regcpy);

  sim_csrcpy = (void (*)(size_t, void *, bool))dlsym(handle, "difftest_csrcpy");
  check_and_assert(sim_csrcpy);

  sim_uarchstatus_cpy = (void (*)(size_t, void *, bool))dlsym(handle, "difftest_uarchstatus_cpy");
  check_and_assert(sim_uarchstatus_cpy);

  sim_exec = (void (*)(size_t, uint64_t))dlsym(handle, "difftest_exec");
  check_and_assert(sim_exec);

  sim_guided_exec = (vaddr_t (*)(size_t, void *))dlsym(handle, "difftest_guided_exec");
  check_and_assert(sim_guided_exec);

  sim_update_config = (void (*)(size_t, void *))dlsym(handle, "update_dynamic_config");
  check_and_assert(sim_update_config);

  sim_store_commit = (int (*)(size_t, uint64_t*, uint64_t*, uint8_t*))dlsym(handle, "difftest_store_commit");
  check_and_assert(sim_store_commit);

  sim_raise_intr = (void (*)(size_t, uint64_t))dlsym(handle, "difftest_raise_intr");
  check_and_assert(sim_raise_intr);

  sim_isa_reg_display = (void (*)(size_t))dlsym(handle, "isa_reg_display");
  check_and_assert(sim_isa_reg_display);

  // core independent
  sim_debug_mem_sync = (void (*)(paddr_t, void *, size_t))dlsym(handle, "debug_mem_sync");
  check_and_assert(sim_debug_mem_sync);

  sim_query = (void (*)(size_t, void*, uint64_t))dlsym(handle, "difftest_query_ref");
#ifdef ENABLE_RUNHEAD
  check_and_assert(sim_query);
#endif

  // core independent
  sim_load_flash_bin = (void (*)(void*, size_t))dlsym(handle, "difftest_load_flash");;

  auto spike_misc_put_gmaddr = (void (*)(void*))dlsym(handle, "difftest_put_gmaddr");
  if (NUM_CORES > 1) {
    check_and_assert(spike_misc_put_gmaddr);
    assert(goldenMem);
    spike_misc_put_gmaddr(goldenMem);
  }
  
  sim_init();
}

void SpikeProxy::memcpy(paddr_t nemu_addr, void *dut_buf, size_t n, bool direction)
{
  sim_memcpy(coreid, nemu_addr, dut_buf, n, direction);
}

void SpikeProxy::regcpy(void *dut, bool direction)
{
  sim_regcpy(coreid, dut, direction);
}

void SpikeProxy::csrcpy(void *dut, bool direction)
{
  sim_csrcpy(coreid, dut, direction);
}

void SpikeProxy::uarchstatus_cpy(void *dut, bool direction)
{
  sim_uarchstatus_cpy(coreid, dut, direction);
}

int SpikeProxy::store_commit(uint64_t *saddr, uint64_t *sdata, uint8_t *smask)
{
  return sim_store_commit(coreid, saddr, sdata, smask);
}

void SpikeProxy::exec(uint64_t n)
{
  sim_exec(coreid, n);
}

vaddr_t SpikeProxy::guided_exec(void *disambiguate_para)
{
  return sim_guided_exec(coreid, disambiguate_para);
}

void SpikeProxy::update_config(void *config)
{
  sim_update_config(coreid, config);
}

void SpikeProxy::raise_intr(uint64_t no)
{
  sim_raise_intr(coreid, no);
}

void SpikeProxy::isa_reg_display()
{
  sim_isa_reg_display(coreid);
}

void SpikeProxy::query(void *result_buffer, uint64_t type)
{
  sim_query(coreid, result_buffer, type);
}
