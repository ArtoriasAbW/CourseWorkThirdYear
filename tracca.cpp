#include <cstdio>
#include <cstddef> /* for offsetof */
#include <fstream>
#include <vector>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

#include "utils.h"
#include "format.pb.h"

static FILE *modules_info;


// protobuf
static TraceFormat::Trace trace;
static TraceFormat::TraceHeader trace_hdr;
static TraceFormat::BasicBlock cur_bb;
static TraceFormat::Record cur_record;
static TraceFormat::Insruction cur_instr;
static std::vector<const module_data_t *> modules;

enum {
    REF_TYPE_READ = 0,
    REF_TYPE_WRITE = 1,
};

typedef struct _mem_ref_t {
    ushort type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
    ushort size; /* mem ref size or instr length */
    app_pc addr; /* mem ref addr or instr pc */
} mem_ref_t;

/* Max number of mem_ref a buffer can have.
 */
#define MAX_NUM_MEM_REFS 4096
/* The maximum size of buffer for holding mem_refs. */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

/* thread private log file and counter */
typedef struct {
    byte *seg_base;
    mem_ref_t *buf_base;
    file_t log;
    FILE *logf;
    uint64 num_refs;
} per_thread_t;

static client_id_t client_id;
static void *mutex;     /* for multithread support */
static uint64 num_refs; /* keep a global memory reference count */

/* Allocated TLS slot offsets */
enum {
    MEMTRACE_TLS_OFFS_BUF_PTR,
    MEMTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base) *(mem_ref_t **)TLS_SLOT(tls_base, MEMTRACE_TLS_OFFS_BUF_PTR)



int get_module_idx_by_address(app_pc address) {
    for (int i = 0; i < modules.size(); ++i) {
        if (dr_module_contains_addr(modules[i], address)) {
            return i;
        }
    }
    return -1;
}
// если type > 1 заполняем информацию об инструкции и ждем пока появится следующая инструкция
// добавляем эту инструкцию в рекорд, очищаем и заполняем новую
// если type <= 0 заполняем информацию об операндах инструкции cur_instr
static void
memtrace(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    mem_ref_t *buf_ptr = BUF_PTR(data->seg_base);

    for (mem_ref_t *mem_ref = (mem_ref_t *)data->buf_base; mem_ref < buf_ptr; mem_ref++) {
        fprintf(data->logf, "" PIFX ": %2d, %s\n", (ptr_uint_t)mem_ref->addr,
                mem_ref->size,
                (mem_ref->type > REF_TYPE_WRITE)
                    ? decode_opcode_name(mem_ref->type) /* opcode for instr */
                    : (mem_ref->type == REF_TYPE_WRITE ? "w" : "r"));
        data->num_refs++;
    }
    BUF_PTR(data->seg_base) = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
// скорее всего мы хотим иметь для каждого треда отдельный файл
// здесь надо заполнять Record (перед этим заполнив instruction) и закинуть этот Record в BasicBlock (
// вообще возможно стоит несколько изменить структуру)
/*
    TraceFormat::Record
*/
static void
clean_call(app_pc instr_addr)
{
    // TraceFormat::Record record;
    // проверить type
    // record.set_allocated_insruction()
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);
    TraceFormat::Register xax;
    xax.set_name("xax");
    xax.set_value(mc.xax);
    TraceFormat::Register xbx;
    xbx.set_name("xbx");
    xbx.set_value(mc.xbx);
    TraceFormat::Register xcx;
    xcx.set_name("xcx");
    xcx.set_value(mc.xcx);
    TraceFormat::Register xdx;
    xdx.set_name("xdx");
    xdx.set_value(mc.xdx);
    TraceFormat::Register xbp;
    xbp.set_name("xbp");
    xbp.set_value(mc.xbp);
    cur_record.mutable_registers()->Add(std::move(xax));
    cur_record.mutable_registers()->Add(std::move(xbx));
    cur_record.mutable_registers()->Add(std::move(xcx));
    cur_record.mutable_registers()->Add(std::move(xdx));
    cur_record.mutable_registers()->Add(std::move(xdx));
    fprintf(data->logf, "REGS: xax=%lx, xbx=%lx, xcx=%lx, xdx=%lx, xbp=%lx\n",
          mc.xax, mc.xbx, mc.xcx, mc.xdx, mc.xsp);
    memtrace(drcontext);
    cur_bb.mutable_records->Add(std::move(cur_record));
    cur_record.Clear();
}

static void
insert_load_buf_ptr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_ptr)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void
insert_update_buf_ptr(void *drcontext, instrlist_t *ilist, instr_t *where,
                      reg_id_t reg_ptr, int adjust)
{
    instrlist_meta_preinsert(
        ilist, where,
        XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void
insert_save_type(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                 reg_id_t scratch, ushort type)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2); 
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), // type in scratch
                                  OPND_CREATE_INT16(type)));
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base, offsetof(mem_ref_t, type)),  // scrath in sbase + offset 
                                      opnd_create_reg(scratch)));
}

static void
insert_save_size(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                 reg_id_t scratch, ushort size)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                    OPND_CREATE_INT16(size)));
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base, offsetof(mem_ref_t, size)),
                                      opnd_create_reg(scratch)));
}

static void
insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
               reg_id_t scratch, app_pc pc)
{
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch),
                                     ilist, where, NULL, NULL);
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(base, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(scratch)));
}

static void
insert_save_addr(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
                 reg_id_t reg_ptr, reg_id_t reg_addr)
{
    /* we use reg_ptr as scratch to get addr */
    bool ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr); // ref in reg_addr
    DR_ASSERT(ok);
    insert_load_buf_ptr(drcontext, ilist, where, reg_ptr); // reg_ptr <- needed address
    instrlist_meta_preinsert(ilist, where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(reg_ptr, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(reg_addr)));
}

/* insert inline code to add an instruction entry into the buffer */
static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    /* we don't want to predicate this, because an instruction fetch always occurs */
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
    insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp,
                     (ushort)instr_get_opcode(where));
    insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp,
                     (ushort)instr_length(drcontext, where));
    insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(where));
    insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
    instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

/* insert inline code to add a memory reference info entry into the buffer */
static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
               bool write)
{
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    /* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref */
    insert_save_addr(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
    insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp,
                     write ? REF_TYPE_WRITE : REF_TYPE_READ);
    insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp,
                     (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
    insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

/* For each memory reference app instr, we insert inline code to fill the buffer
 * with an instruction entry and memory reference entries.
 */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data) {
    

    // если новый базовый блок, добавляем старый в протобаф, очищаем текущий и заполняем хедер для нового.
    static void *old_tag = nullptr;
    if (old_tag != nullptr && old_tag != tag) {
        trace.mutable_data()->Add(std::move(cur_bb));
        cur_bb.Clear();
        TraceFormat::BasicBlockHeader bb_hdr;
        bb_hdr.set_module_id(get_module_idx_by_address(dr_fragment_app_pc(tag)));
        bb_hdr.set_thread_id(1); // only one thread now   
        tag = old_tag;
    }

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    if (!instr_reads_memory(instr) && !instr_writes_memory(instr))
        return DR_EMIT_DEFAULT;

    /* insert code to add an entry for app instruction */
    instrument_instr(drcontext, bb, instr);

    /* insert code to add an entry for each memory reference opnd */
    if (instr_reads_memory(instr) || instr_writes_memory(instr)) {
        for (int i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i)))
                instrument_mem(drcontext, bb, instr, instr_get_src(instr, i), false);
        }

        for (int i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i)))
                instrument_mem(drcontext, bb, instr, instr_get_dst(instr, i), true);
        }

    }

    dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call, false, 1, OPND_CREATE_INTPTR(instr));

    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                 bool translating)
{
    if (!drutil_expand_rep_string(drcontext, bb)) {
        DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    }
    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = (byte *)dr_get_dr_segment_base(tls_seg);
    data->buf_base =
        (mem_ref_t *)dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);
    /* put buf_base to TLS as starting buf_ptr */
    BUF_PTR(data->seg_base) = data->buf_base;

    data->num_refs = 0;

    data->log =
        log_file_open(client_id, drcontext, NULL /* using client lib path */, "memtrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
    fprintf(data->logf, "Format: <data address>: <data size>, <(r)ead/(w)rite/opcode>\n");
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;
    memtrace(drcontext); /* dump any remaining buffer entries */
    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);
    log_stream_close(data->logf); /* closes fd too */
    dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}


static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    modules.push_back(info);
    fprintf(modules_info, "module:%s start[%p] end[%p]\n\n", info->full_path, info->start, info->end);
}

static void
event_exit(void)
{
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' num refs seen: " SZFMT "\n", num_refs);
    if (!dr_raw_tls_cfree(tls_offs, MEMTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        !drmgr_unregister_module_load_event(event_module_load) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);


    dr_mutex_destroy(mutex);
    std::ofstream output("trace.out");
    trace.SerializeToOstream(&output);
    output.close();
    drutil_exit();
    drmgr_exit();
    fclose(modules_info);
}


DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = { sizeof(ops), 3, false };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init())
        DR_ASSERT(false);

    /* register events */
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL) ||
        !drmgr_register_module_load_event(event_module_load))
        DR_ASSERT(false);

    client_id = id;
    modules_info = fopen("module_info.txt", "w");

    // TraceFormat::TraceHeader trace_hdr;
    trace_hdr.set_memory_trace(true);
    trace_hdr.set_num_of_reg(5);
    trace.set_allocated_header(&trace_hdr);
    mutex = dr_mutex_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, MEMTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' initializing\n");
}
