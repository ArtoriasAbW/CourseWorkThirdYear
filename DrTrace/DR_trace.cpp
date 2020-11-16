#include "general_headers.h"
#include "modules_info.hpp"

static modules_info mi;

static file_t logfd;
static FILE *logfile;
static app_pc cur_module_loading_address = 0;

#if defined(X86_64)
typedef int64_t platform_int_t;
#elif defined(X86_32)
typedef int32_t platform_int_t;
#endif

static void
instrument_memory_write(instr_t *instr) {
    size_t size;
    opnd_t ref;
    for (int i = 0; i < instr_num_dsts(instr); ++i) {
        opnd_t dst = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(dst)) {
            size = drutil_opnd_mem_size_in_bytes(dst, instr);
            fprintf(logfile, "(w) dst:? size:%lu ", size);
        }
    }
}

static void
process_instr(app_pc instr_addr, platform_int_t offset) {

  void *drcontext = dr_get_current_drcontext();
  instr_t instr;
  instr_init(drcontext, &instr);
  instr_reset(drcontext, &instr);
  dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};

  app_pc next_pc = decode(drcontext, instr_addr, &instr);
  int opcode = instr_get_opcode(&instr);
  const char *opcode_name = decode_opcode_name(opcode);
  dr_get_mcontext(drcontext, &mc);
  #if defined(X86_64)
  fprintf(logfile, "[%p]:off=%ld %03X - %-6s ", instr_addr, offset, opcode, opcode_name);
  if (instr_writes_memory(&instr)) {
      instrument_memory_write(&instr);
  }
  fprintf(logfile, "REGS: rax=%lx, rbx=%lx, rcx=%lx, rdx=%lx, rflags=%lx\n", mc.rax, mc.rbx, mc.rcx, mc.rdx, mc.rflags);
  #elif defined(X86_32)
  fprintf(logfile, "[%p]:off=%d %03X - %-6s ", instr_addr, offset, opcode, opcode_name);
   if (instr_writes_memory(&instr)) {
      instrument_memory_write(&instr);
  }
  fprintf(logfile, "REGS: eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, eflags=%lx\n", mc.eax, mc.ebx, mc.ecx, mc.edx, mc.eflags);
  #endif
  instr_free(drcontext, &instr);
}

static dr_emit_flags_t 
event_app_instruction(void *drcontext, void *tag,
                                             instrlist_t *bb, instr_t *instr,
                                             bool for_trace, bool translating,
                                             OUT void *user_data) {   

  static void *prev_tag = NULL;
  static uint prev_module_idx = 0;
  static bool need_trace = true;
  app_pc ptr = instr_get_app_pc(instr);                           
  if (prev_tag != tag) {
    thread_id_t thread_id = dr_get_thread_id(drcontext);

    if (!(prev_module_idx && mi.check_ptr_in_module(ptr, prev_module_idx))) {
      prev_module_idx = mi.get_module_id(ptr);
      need_trace = mi.need_to_trace(prev_module_idx);
    }
    if (!prev_module_idx) {
        fprintf(logfile, "\n[%p] [thread id = %u] [code is outside modules]:\n", ptr, thread_id);
    } else {
        fprintf(logfile, "\n[%p] [thread id = %u] [module id = %d]:\n", ptr, thread_id, prev_module_idx);
    }
    prev_tag = tag;
  }
  if (!need_trace)return DR_EMIT_DEFAULT;
  int64_t m_offset = ptr - mi.get_module_start(prev_module_idx);
 
  {
      #if defined(X86_64)
      opnd_t clean_call_1_param = OPND_CREATE_INT64(m_offset);
      #elif defined(X86_32)
      opnd_t clean_call_1_param = OPND_CREATE_INT32(m_offset);
      #endif
      dr_insert_clean_call(drcontext, bb, instr, (void *)process_instr, false, 2, OPND_CREATE_INTPTR(instr_get_app_pc(instr)), clean_call_1_param);
  }

  return DR_EMIT_DEFAULT;
}


static void 
event_exit(void) {
    
    fclose(logfile);
    
    bool all_unreg = true;
    all_unreg &= drmgr_unregister_bb_insertion_event(event_app_instruction);
    if (!all_unreg) {
        dr_fprintf(STDERR, "not all event handlers were unregistered\n");
    }
    
    mi.mi_free();

    drmgr_exit();
}

DR_EXPORT void 
dr_client_main(client_id_t id, int argc, const char **argv) {
#ifdef WINDOWS
  dr_enable_console_printing();
#endif
  if (!drmgr_init()) { 
      dr_fprintf(STDERR, "failed to drmgr extension initialize\n");
      DR_ASSERT(false); 
  }

  dr_register_exit_event(event_exit);
  //for example : mi.module_add_not_trace_by_path("avast", StringWayMatching::contain_case_insensitive);

  if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL)) {
    dr_fprintf(STDERR, "bb_instrumentation_event handler wasn't created\n");
    DR_ASSERT(false);
  }
  bool trace_file_specified = false;
  bool modules_file_specified = false;
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-mf") && i != argc - 1) {
      mi = modules_info(argv[i + 1]);
      modules_file_specified = true;
    } else if (!strcmp(argv[i], "-tf") && i != argc - 1) {
      logfd = dr_open_file(argv[i + 1], DR_FILE_WRITE_OVERWRITE);
      trace_file_specified = true;
    }
  }

  if (!modules_file_specified) {
    dr_fprintf(STDERR, "need to specify file for modules\n");
    DR_ASSERT(false);
  }

  if (!trace_file_specified) {
    dr_fprintf(STDERR, "need to specify file for trace\n");
    DR_ASSERT(false);
  }
  if (logfd == INVALID_FILE) {
    dr_fprintf(STDERR, "cannot open file");
    DR_ASSERT(false);
  }
  logfile = fdopen(logfd, "w+");
}
