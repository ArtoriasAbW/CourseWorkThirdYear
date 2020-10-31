#include "modules_info.hpp"

static modules_info mi("module.txt");

static file_t logfd;
static FILE *logfile;
static app_pc cur_module_loading_address = 0;


static void
process_instr(app_pc instr_addr, int64_t offset) {
  void *drcontext = dr_get_current_drcontext();
  instr_t instr;
  instr_init(drcontext, &instr);
  instr_reset(drcontext, &instr);
  dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
  app_pc next_pc = decode(drcontext, instr_addr, &instr);
  int opcode = instr_get_opcode(&instr);
  const char *opcode_name = decode_opcode_name(opcode);
  fprintf(logfile, "[%p]:off=%ld %03X - %-6s ", instr_addr, offset, opcode, opcode_name);
  dr_get_mcontext(drcontext, &mc);
  fprintf(logfile, "REGS: rax=%lx, rbx=%lx, rcx=%lx, rdx=%lx, rflags=%lx\n", mc.rax, mc.rbx, mc.rcx, mc.rdx, mc.rflags);
  instr_free(drcontext, &instr);
}

static dr_emit_flags_t 
event_app_instruction(void *drcontext, void *tag,
                                             instrlist_t *bb, instr_t *instr,
                                             bool for_trace, bool translating,
                                             OUT void *user_data) {   

  static void *prev_tag = NULL;
  static uint prev_module_idx = 0;
  app_pc ptr = instr_get_app_pc(instr);                           
  if (prev_tag != tag) {
    thread_id_t thread_id = dr_get_thread_id(drcontext);

    if (!(prev_module_idx && mi.check_ptr_in_module(ptr, prev_module_idx))) {
      prev_module_idx = mi.get_module_id(ptr);
    }
    if (!prev_module_idx) {
      fprintf(logfile, "[%p] [thread id = %u] [code is outside modules]:\n", ptr, thread_id);
    } else {
      fprintf(logfile, "[%p] [thread id = %u] [module id = %d]:\n", mi.modules[prev_module_idx].start, thread_id, mi.modules[prev_module_idx].id);
    }
    prev_tag = tag;
  }

  int64_t m_offset = ptr - mi.modules[prev_module_idx].start;
 
  dr_insert_clean_call(drcontext, bb, instr, (void *)process_instr, false, 2, OPND_CREATE_INTPTR(instr_get_app_pc(instr)), OPND_CREATE_INT64(m_offset));

  return DR_EMIT_DEFAULT;
}


static void 
event_exit(void) {
  drmgr_unregister_bb_insertion_event(event_app_instruction);
  log_stream_close(logfile);
  mi.mi_free();
  drmgr_exit();
}

DR_EXPORT void 
dr_client_main(client_id_t id, int arcg, const char **argv) {
  dr_register_exit_event(event_exit);
  if (!drmgr_init()) {
    DR_ASSERT(false);
  }

  if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL)) {
    dr_fprintf(STDERR, "bb_instrumentation_event handler wasn't created\n");
    DR_ASSERT(false);
  }

  logfd = log_file_open(id, NULL, NULL, "trace", DR_FILE_ALLOW_LARGE);
  if (logfd == INVALID_FILE) {
    dr_fprintf(STDERR, "cannot open file");
    DR_ASSERT(false);
  }
  logfile = log_stream_from_file(logfd);
}
