/***************************************************************************************
* Copyright (c) 2020-2023 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
*
* DiffTest is licensed under Mulan PSL v2.
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

uint8_t* goldenMem = NULL;
const char *difftest_ref_so = NULL;

#define check_and_assert(func)                                \
  do {                                                        \
    if (!func) {                                              \
      printf("ERROR: %s\n", dlerror());  \
      assert(func);                                           \
    }                                                         \
  } while (0);

NemuProxy::NemuProxy(int coreid, size_t ram_size = 0) {
  bool use_given_diff = true;
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
    use_given_diff = false;
  }

  printf("NemuProxy using %s\n", difftest_ref_so);

  handle = dlmopen(LM_ID_NEWLM, difftest_ref_so, RTLD_LAZY | RTLD_DEEPBIND);
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

  set_ramsize = (void (*)(size_t size)) dlsym(handle, "difftest_set_ramsize");
  check_and_assert(set_ramsize);

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

  if(ram_size){
    set_ramsize(ram_size); // set ram_size before nemu_init()
  }

  nemu_init();

  if (!use_given_diff) {
    free((void *)difftest_ref_so);
    difftest_ref_so = nullptr;
  }
}

void ref_misc_put_gmaddr(uint8_t* ptr) {
  goldenMem = ptr;
}

SpikeProxy::SpikeProxy(int coreid, size_t ram_size = 0) {
  bool use_given_diff = true;
  if (difftest_ref_so == NULL) {
    printf("--diff is not given, "
        "try to use $(" SPIKE_ENV_VARIABLE ")/" SPIKE_SO_FILENAME " by default\n");
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
    use_given_diff = false;
  }

  printf("SpikeProxy using %s\n", difftest_ref_so);

  void *handle = dlmopen(LM_ID_NEWLM, difftest_ref_so, RTLD_LAZY | RTLD_DEEPBIND);
  if (!handle) {
    printf("%s\n", dlerror());
    assert(0);
  }

  auto spike_init = (void (*)(int))dlsym(handle, "difftest_init");
  check_and_assert(spike_init);

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

#ifdef DEBUG_MODE_DIFF
  debug_mem_sync = (void (*)(paddr_t, void *, size_t))dlsym(handle, "debug_mem_sync");
  check_and_assert(debug_mem_sync);
#endif

  query = (void (*)(void*, uint64_t))dlsym(handle, "difftest_query_ref");
#ifdef ENABLE_RUNHEAD
  check_and_assert(query);
#endif

  auto spike_difftest_set_mhartid = (void (*)(int))dlsym(handle, "difftest_set_mhartid");
  if (NUM_CORES > 1) {
    check_and_assert(spike_difftest_set_mhartid);
    spike_difftest_set_mhartid(coreid);
  }

  auto spike_misc_put_gmaddr = (void (*)(void*))dlsym(handle, "difftest_put_gmaddr");
  if (NUM_CORES > 1) {
    check_and_assert(spike_misc_put_gmaddr);
    assert(goldenMem);
    spike_misc_put_gmaddr(goldenMem);
  }

  if(ram_size){
    printf("Spike ram_size api to be added later, ignore ram_size set\n");
  }

  spike_init(0);

  if (!use_given_diff) {
    free((void *)difftest_ref_so);
    difftest_ref_so = nullptr;
  }
}
