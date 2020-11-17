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

    bool not_trace = mi_self->update_traced_module(module_id);//but we can turn on not tracing rule after load event

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

modules_info::modules_info(const char *file_name) : modules(), valid(true)
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
    traced_modules.insert(0);

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
    
    this->traced_modules = std::move(other.traced_modules);

    this->rules_not_trace_by_id = std::move(other.rules_not_trace_by_id);
    this->except_not_trace_by_id= std::move(other.except_not_trace_by_id);

    this->rules_not_trace_by_name = std::move(other.rules_not_trace_by_name);
    this->except_not_trace_by_name = std::move(other.except_not_trace_by_name);

    this->rules_not_trace_by_path = std::move(other.rules_not_trace_by_path);
    this->except_not_trace_by_path = std::move(other.except_not_trace_by_path);

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

#pragma region traced modules
void modules_info::update_traced_modules()
{
    size_t m_amount = modules.size();
    for (int ind = 0; ind < m_amount; ind++) {
        update_traced_module(ind);
    }
}

#ifndef Module_one_func
#pragma region help
void modules_info::module_add_not_trace_help(std::set<not_trace_rule> &set, const std::string &str, E_StringWayMatching way_matching)
{
    not_trace_rule rule{str, way_matching};
    if (set.insert(rule).second) {
        update_traced_modules();
    }
}

void modules_info::module_del_not_trace_help(std::set<not_trace_rule> &set, const std::string &name, E_StringWayMatching way_matching)
{
    if (set.erase(not_trace_rule {name, way_matching, false})) {
        update_traced_modules();
    }
}
#pragma endregion

#pragma region by id
void modules_info::module_add_not_trace_rule_by_id(size_t id)
{
    rules_not_trace_by_id.insert(id);
    if (need_to_trace(id))update_traced_module(id);
}

void modules_info::module_del_not_trace_rule_by_id(size_t id)
{
    if (rules_not_trace_by_id.erase(id)) {
        update_traced_modules();
    }
}

void modules_info::module_add_not_trace_exception_by_id(size_t id)
{
    except_not_trace_by_id.insert(id);
    if (!need_to_trace(id))traced_modules.insert(id);
}

void modules_info::module_del_not_trace_exception_by_id(size_t id)
{
    if (except_not_trace_by_id.erase(id)) {
        update_traced_modules();
    }
}
#pragma endregion

#pragma region by name
void modules_info::module_add_not_trace_rule_by_name(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_add_not_trace_help(rules_not_trace_by_name, name, way_matching);

}

void modules_info::module_add_not_trace_exception_by_name(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_add_not_trace_help(except_not_trace_by_name, name, way_matching);
}

void modules_info::module_del_not_trace_rule_by_name(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_del_not_trace_help(rules_not_trace_by_name, name, way_matching);
}

void modules_info::module_del_not_trace_exception_by_name(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_del_not_trace_help(except_not_trace_by_name, name, way_matching);
}
#pragma endregion

#pragma region by path
void modules_info::module_add_not_trace_rule_by_path(const std::string &path, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_add_not_trace_help(rules_not_trace_by_path, path, way_matching);
}

void modules_info::module_add_not_trace_exception_by_path(const std::string &path, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_add_not_trace_help(except_not_trace_by_path, path, way_matching);
}

void modules_info::module_del_not_trace_rule_by_path(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_del_not_trace_help(rules_not_trace_by_path, name, way_matching);
}
void  modules_info::module_del_not_trace_exception_by_path(const std::string &name, E_StringWayMatching way_matching = E_StringWayMatching::equal)
{
    module_del_not_trace_help(except_not_trace_by_path, name, way_matching);
}
#pragma endregion
#endif

#ifdef Module_one_func
void modules_info::change_traced_modules(E_ModuleRuleAction mr_act, E_ModuleRuleType mr_type, const ModuleRule &m_rule)
{
    auto mr_by = m_rule.get_ModuleRule_By();
    bool b_not_trace_rule = (mr_type == E_ModuleRuleType::not_trace_rule);

    if (mr_by == E_ModuleRuleBy::by_id) {
        auto& set_id = b_not_trace_rule ? rules_not_trace_by_id : except_not_trace_by_id;
        const ModuleRuleById &mr_by_id = ((const ModuleRuleById &)(m_rule));//TODO:OK?
        size_t id = mr_by_id.module_id;

        if (mr_act == E_ModuleRuleAction::Add) {
            set_id.insert(id);
            if(b_not_trace_rule && need_to_trace(id))update_traced_module(id);
            if(!b_not_trace_rule && !need_to_trace(id))traced_modules.insert(id);
        } else if (mr_act == E_ModuleRuleAction::Delete) {
            if (set_id.erase(id)) {
                update_traced_modules();
            }
        }
        return;
    }

    std::set<not_trace_rule> &set =
        (b_not_trace_rule) ?
        ((mr_by == E_ModuleRuleBy::by_name) ? rules_not_trace_by_name : rules_not_trace_by_path) :
        ((mr_by == E_ModuleRuleBy::by_name) ? except_not_trace_by_name : except_not_trace_by_path);

    const ModuleRuleByStr &mr_by_str = ((const ModuleRuleByStr &)(m_rule));//TODO:OK?

    if (mr_act == E_ModuleRuleAction::Add) {
        if (set.insert(not_trace_rule{mr_by_str.str, mr_by_str.swm}).second) {
            update_traced_modules();
        }
    } else if (mr_act == E_ModuleRuleAction::Delete) {
        if (set.erase(not_trace_rule {mr_by_str.str, mr_by_str.swm, false})) {
            update_traced_modules();
        }
    }
}
#endif

bool modules_info::try_one_rule(const not_trace_rule &rule, size_t module_info_id, std::string &str, std::string &lowercase_str, E_ModuleRuleType upd_type)
{
    //if(upd_type == E_ModuleRuleType::all)error;

    size_t ind = module_info_id;
    if (!ind || !modules[ind].id)return false;

    switch (rule.way_matching) {
    case E_StringWayMatching::equal:
        if (!(rule.str == str)) return false;
        break;

    case E_StringWayMatching::equal_case_insensitive:
        if (lowercase_str.empty())lowercase_str = str_to_lowercase(str);
        if (!(rule.lowercase_str == lowercase_str)) return false;
        break;

    case E_StringWayMatching::contain:
        if (str.find(rule.str) == std::string::npos) return false;
        break;

    case E_StringWayMatching::contain_case_insensitive:
        if (lowercase_str.empty())lowercase_str = str_to_lowercase(str);
        if (lowercase_str.find(rule.lowercase_str) == std::string::npos) return false;
        break;
    }
    if(upd_type == E_ModuleRuleType::not_trace_rule)traced_modules.erase(ind);
    else if(upd_type == E_ModuleRuleType::not_trace_exception)traced_modules.insert(ind);
    return true;
}

bool modules_info::try_rules(const std::set<not_trace_rule> &set, size_t module_info_id, std::string &str, E_ModuleRuleType upd_type)
{
    size_t ind = module_info_id;
    if (modules[ind].id == 0)return false;

    std::string lowercase_str {};

    for (auto &rule : set) {
        if (try_one_rule(rule, module_info_id, str, lowercase_str, upd_type))return true;
    }

    return false;
}

bool modules_info::update_traced_module(size_t module_info_id)
{
    size_t id = module_info_id;

    if (id == 0) {
        if (except_not_trace_by_id.count(id)) {
            traced_modules.insert(id);
            return false;
        }

        if (rules_not_trace_by_id.count(id)) {
            traced_modules.erase(id);
            return true;
        }

        traced_modules.insert(id);
        return false;
    }
    if (modules[id].id == 0 || modules[id].m_data == NULL)return false;

    if (except_not_trace_by_id.count(id)) {
        traced_modules.insert(id);
        return false;
    }
    
    std::string prefer_name = std::string(dr_module_preferred_name(modules[id].m_data));
    std::string path = std::string(modules[id].m_data->full_path);

    if (try_rules(except_not_trace_by_name, id, prefer_name, E_ModuleRuleType::not_trace_exception))return false;
    if (try_rules(except_not_trace_by_path, id, path, E_ModuleRuleType::not_trace_exception))return false;

    if (rules_not_trace_by_id.count(id)) {
        traced_modules.erase(id);
        return true;
    }

    if (try_rules(rules_not_trace_by_name, id, prefer_name, E_ModuleRuleType::not_trace_rule))return true;
    if (try_rules(rules_not_trace_by_path, id, path, E_ModuleRuleType::not_trace_rule))return true;

    traced_modules.insert(id);
    return false;
}

bool modules_info::need_to_trace(size_t module_info_id)
{
    return traced_modules.count(module_info_id);
}
#pragma endregion


