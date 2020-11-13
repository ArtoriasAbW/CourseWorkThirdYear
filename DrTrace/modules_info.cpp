#include "modules_info.hpp"

static modules_info *mi_self = NULL;

#pragma region check module info
inline bool modules_info::check_ptr_in_module(app_pc ptr, size_t index)
{
    return modules[index].id && modules[index].start <= ptr && ptr < modules[index].end && dr_module_contains_addr(modules[index].m_data, ptr);
}

size_t modules_info::get_module_id(app_pc ptr)
{
    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        if (check_ptr_in_module(ptr, i)) return i;
    }
    return 0;
}

app_pc modules_info::get_module_start(size_t index)
{
    return modules[index].start;
}
#pragma endregion

#pragma region Static Function : module load/unload event
void
modules_info::module_load_event(void *drcontext, const module_data_t *info, bool loaded)
{

    static uint module_id = 0;
    module_id++;

    mi_self->modules.push_back(__module_info(module_id, info->start, info->end, dr_copy_module_data(info)));

    bool not_trace = mi_self->not_trace_rules_on(module_id);//but we can turn on not tracing rule after load event

    dr_fprintf(mi_self->module_info_file, "[id = %04d]: [name = \"%s\"     path = \"%s\"]\n", module_id, dr_module_preferred_name(info), info->full_path);
    dr_fprintf(mi_self->module_info_file, "             [start = [%p]     end = [%p]]\n", info->start, info->end);
    if(not_trace)
    dr_fprintf(mi_self->module_info_file, "             [not initially traced]\n");
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
#pragma endregion

#pragma region Constructor

modules_info::modules_info(const char *file_name) : modules(), trace_blacklist(), valid(true), rules_not_trace_by_name(), rules_not_trace_by_path()
{   
    if (mi_self != NULL) {
        dr_fprintf(STDERR, "TODO: remove static (if it possible)\n");
        DR_ASSERT(false);
    }
    if (!drmgr_init()) { 
        dr_fprintf(STDERR, "failed to drmgr extension initialize\n");
        DR_ASSERT(false); 
    }

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

#pragma endregion

#pragma region operator(s)
modules_info &
modules_info::operator= (modules_info &&other) noexcept
{
    if (this->valid) {
        this->~modules_info();
    }

    this->valid = other.valid;
    this->modules = std::move(other.modules);
    this->module_info_file = std::move(other.module_info_file);
    
    this->trace_blacklist = std::move(other.trace_blacklist);
    this->rules_not_trace_by_name = std::move(other.rules_not_trace_by_name);
    this->rules_not_trace_by_path = std::move(other.rules_not_trace_by_path);

    other.valid = false;
    mi_self = this;
    return *this;
}
#pragma endregion

#pragma region Free

bool modules_info::mi_free()
{
    if (!mi_self || !valid)return true;

    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        if (modules[i].id) {
            modules[i].id = 0;
            dr_free_module_data(modules[i].m_data);
        }
    }
   
    dr_close_file(module_info_file);

    bool ret = drmgr_unregister_module_load_event(module_load_event);
    ret = drmgr_unregister_module_unload_event(module_unload_event) & ret;
    
    valid = false;
    mi_self = NULL;

    drmgr_exit();
    
    return ret;
}

modules_info::~modules_info()
{
    if (!mi_self || !valid)return;

    if (!mi_free()) {
        dr_fprintf(STDERR, "not all moudle event handlers were unregistered\n");
    }
}

#pragma endregion


//+++ out from this file:

//TODO:not only eng chars.  (other language?)
std::string str_to_lowercase(char *str)
{
    size_t len = std::strlen(str);
    std::string ret;
    ret.reserve(len);

    for (int i = 0; i < len; i++) {
        ret += std::tolower(str[i]);
    }
    
    return ret;
}

std::string str_to_lowercase(std::string str)
{
    size_t len = str.length();
    std::string ret;
    ret.reserve(len);

    for (int i = 0; i < len; i++) {
        ret += std::tolower(str[i]);
    }

    return ret;
}
//--- out from this file:


#pragma region add in trace blacklist
void modules_info::module_add_not_trace_by_id(size_t id)
{trace_blacklist.insert(id);}

size_t modules_info::module_add_not_trace_by_name(const std::string &name, StringWayMatching way_matching = StringWayMatching::equal)
{
    size_t ret = 0;
    not_trace_rule rule = {name, str_to_lowercase(name), way_matching};
    rules_not_trace_by_name.push_back(rule);

    size_t m_amount = modules.size();
    for (int ind = 0; ind < m_amount; ind++) {
        std::string lowercase_str {};
        if (modules[ind].id == 0 || (modules[ind].m_data == NULL))continue;
        ret += try_one_rule(rule, ind, dr_module_preferred_name(modules[ind].m_data), lowercase_str);
    }

    return ret;
}

size_t modules_info::module_add_not_trace_by_path(const std::string &path, StringWayMatching way_matching = StringWayMatching::equal)
{
    size_t ret = 0;
    not_trace_rule rule = {path, str_to_lowercase(path), way_matching};
    rules_not_trace_by_path.push_back(rule);
    size_t m_amount = modules.size();
    for (int ind = 0; ind < m_amount; ind++) {
        std::string lowercase_str{};
        if (modules[ind].id == 0 || (modules[ind].m_data == NULL))continue;
        ret += try_one_rule(rule, ind, modules[ind].m_data->full_path, lowercase_str);
    }
    return ret;
}

bool modules_info::try_one_rule(const not_trace_rule &rule, size_t module_info_id, const char *str, std::string &lowercase_str, bool with_insert)
{
    size_t ind = module_info_id;
    if (!ind || !modules[ind].id)return false;

    switch (rule.way_matching) {
    case StringWayMatching::equal:
        if (!(rule.str == str)) return false;
        break;

    case StringWayMatching::equal_case_insensitive:
        if (lowercase_str.empty())lowercase_str = str_to_lowercase(str);
        if (!(rule.lowercase_str == lowercase_str)) return false;
        break;

    case StringWayMatching::contain:
        if (rule.str.find(str) == std::string::npos) return false;
        break;

    case StringWayMatching::contain_case_insensitive:
        if (lowercase_str.empty())lowercase_str = str_to_lowercase(str);
        if (lowercase_str.find(rule.lowercase_str) == std::string::npos) return false;
        break;
    }
    if (with_insert)trace_blacklist.insert(ind);
    return true;
}

bool modules_info::try_rules(const std::vector<not_trace_rule> &rules_not_trace, size_t module_info_id, const char *str, bool with_insert)
{
    size_t ind = module_info_id;
    if (modules[ind].id == 0)return false;

    std::string lowercase_str {};

    for (auto &rule : rules_not_trace) {
        if (try_one_rule(rule, module_info_id, str, lowercase_str, with_insert))return true;
    }

    return false;
}

bool modules_info::not_trace_rules_on(size_t module_info_id)
{
    size_t ind = module_info_id;
    if (modules[ind].id == 0 || (modules[ind].m_data == NULL))return false;

    const char *prefer_name = dr_module_preferred_name(modules[ind].m_data);
    const char *path = modules[ind].m_data->full_path;

    if (try_rules(rules_not_trace_by_name, module_info_id, prefer_name))return true;
    if (try_rules(rules_not_trace_by_path, module_info_id, path))return true;

    return false;
}

bool modules_info::need_to_trace(size_t module_info_id)
{
    return !trace_blacklist.count(module_info_id);
}
#pragma endregion


