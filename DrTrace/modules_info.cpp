#include "modules_info.hpp"


static modules_info *mi_self = NULL;// TODO: remove static (if it possible)

inline bool modules_info::check_ptr_in_module(app_pc ptr, size_t index) // OK
{
    return modules[index].id && dr_module_contains_addr(modules[index].m_data, ptr);
}

size_t modules_info::get_module_id(app_pc ptr) // OK
{
    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        if (check_ptr_in_module(ptr, i)) return i;
    }
    return 0;
}

app_pc modules_info::get_module_start(size_t index) // OK
{
    return modules[index].start;
}

void
modules_info::module_load_event(void *drcontext, const module_data_t *info, bool loaded) // OK
{
    static uint module_id = 0;
    module_id++;

    mi_self->modules.push_back(__module_info(module_id, info->start, info->end, dr_copy_module_data(info)));

    dr_fprintf(mi_self->module_info_file, "[id = %04d]:[name = \"%s\"     path = \"%s\"]\n", module_id, dr_module_preferred_name(info), info->full_path);
}

void
modules_info::module_unload_event(void *drcontext, const module_data_t *info)
{
    dr_fprintf(STDERR, "unload module: dr_context = %p\n", drcontext);//TODO:DEL

    size_t len = mi_self->modules.size();
    for (size_t i = 0; i < len; i++) {
        auto &mi = mi_self->modules[i];
        if (mi.id) {
            if (info->start == mi.start) {
                mi.id = 0;
                dr_free_module_data(mi.m_data);
                break;
            }
        }
    }
}

modules_info::modules_info(const char *file_name) : modules(), valid(true)
{   
    if (mi_self != NULL) {
        dr_fprintf(STDERR, "TODO: remove static (if it possible)\n");
        DR_ASSERT(false);
    }
    if (!drmgr_init()) { DR_ASSERT(false); }

    mi_self = this; // TODO: remove static (if it possible)

    module_info_file = dr_open_file(file_name, DR_FILE_WRITE_OVERWRITE);
    if (!module_info_file) {
        dr_fprintf(STDERR, "module info file was not opened\n");
        DR_ASSERT(false);
    }
    modules.push_back(__module_info());//for modules[_id].id == _id; 

    if (!drmgr_register_module_load_event(module_load_event) ||
        !drmgr_register_module_unload_event(module_unload_event)){
        dr_fprintf(STDERR, "not all event handlers were created\n");
        DR_ASSERT(false);
    }

}

modules_info &
modules_info::operator= (modules_info &&other) noexcept
{
    if (this->valid) {
        this->~modules_info();
        this->valid = false;
    }
    this->valid = other.valid;
    this->modules = std::move(other.modules);
    this->module_info_file = std::move(other.module_info_file);

    other.valid = false;
    mi_self = this;
    return *this;
}

bool modules_info::mi_free()
{
    if (!mi_self || !valid) return true;

    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        if (modules[i].id) {
            modules[i].id = 0;
            dr_free_module_data(modules[i].m_data);
        }
    }
    bool ret = drmgr_unregister_module_load_event(module_load_event);
    ret = drmgr_unregister_module_unload_event(module_unload_event) & ret;
    
    valid = false;
    mi_self = NULL;

    return ret;
}

modules_info::~modules_info()
{
    if (!mi_self || !valid) return;

    if (!mi_free()) {
        dr_fprintf(STDERR, "not all moudle event handlers were unregistered\n");
    }
}