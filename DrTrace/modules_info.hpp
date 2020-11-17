#include "general_headers.h"
#include "lowercase_string.h"

//cpp:
#include <vector>
#include <string>
#include <set>
#include <list>
#include <functional>

#define Module_one_func 1

//#include <optional>
//MAYBE: in try_on_rule std::string &lowercase_str -> std::optional<std::string&> lowercase_optional;

typedef struct __module_info
{
    uint id; //module_info valid only if (id != 0)
    app_pc start;
    app_pc end;
    module_data_t *m_data;//only for dr_module_contain_addr, as may not be contiguous
    __module_info() : id(0), start(0), end(0), m_data(NULL) {}
    __module_info(uint _id, app_pc _start, app_pc _end, module_data_t *ptr) : id(_id), start(_start), end(_end), m_data(ptr) {}
}__module_info;


enum class E_StringWayMatching
{
    equal,
    equal_case_insensitive,
    contain,
    contain_case_insensitive,
};

#ifdef Module_one_func
enum class E_ModuleRuleAction
{
    Add,
    Delete,
};

enum class E_ModuleRuleType
{
    not_trace_rule,
    not_trace_exception,
};

enum class E_ModuleRuleByStr
{
    by_name = 1,
    by_path = 2,
};

enum class E_ModuleRuleBy
{
    by_id = 0,
    by_name = static_cast<int>(E_ModuleRuleByStr::by_name),
    by_path = static_cast<int>(E_ModuleRuleByStr::by_path),
};

class ModuleRule
{
protected: 
    E_ModuleRuleBy mr_by;
public:
    E_ModuleRuleBy get_ModuleRule_By() const { return mr_by; }
};

class ModuleRuleById : public ModuleRule
{
public:
    size_t module_id;
    ModuleRuleById(size_t id) : module_id(id) { mr_by = E_ModuleRuleBy::by_id; }
};

class ModuleRuleByStr : public ModuleRule
{
public:
    E_StringWayMatching swm;
    std::string str;
    ModuleRuleByStr(E_ModuleRuleByStr mr_by_str, E_StringWayMatching _swm, std::string String) :str(String), swm(_swm)
    {
        mr_by = static_cast<E_ModuleRuleBy>(mr_by_str);
    }
};
#endif

struct modules_info
{
public:
    static const size_t ID_OUTSIDE_OF_MODULES = 0;
private:
    file_t module_info_file;
    std::vector<__module_info> modules;//MAYBE:<module_info *>   |   now, while we have only 4 fields so ptr is needless  
                                       //MAYBE: Dictionary<app_pc start, module_info> and find addr between two keys: (key_1 <= pc < key_2) & (pc<=m[key_1].end) => pc in module
    
    /// after  "module_info m_info = m_info_2;"  m_info_2 become invalid;
    /// not valid  =>  don't close module_info_file; don't dr_free_module_data; etc.
    bool valid;
public:
    modules_info() : module_info_file(0), valid(false) {};
    modules_info(const char *file_name);
    modules_info &operator= (modules_info &&other) noexcept;
//free:
    ~modules_info();
    bool mi_free();
//info about module:
    /// <summary>return ptr on start module by id</summary>
    app_pc get_module_start(size_t index);
    bool check_ptr_in_module(app_pc ptr, size_t index);
    /// <summary>return module id != 0 if ptr in module; otherwise return 0</summary>
    size_t get_module_id(app_pc ptr);


private: 
    std::set<size_t> traced_modules {};
    /// <summary>update state of trace for all modules</summary>
    void update_traced_modules();

    struct not_trace_rule
    {
        std::string str;
        std::string lowercase_str;
        E_StringWayMatching way_matching;

        not_trace_rule(std::string _str, E_StringWayMatching _way_matching, bool with_lower = true) :str(_str), way_matching(_way_matching)
        {
            if (with_lower)lowercase_str = str_to_lowercase(str);
            else lowercase_str = "";
        }

        bool operator< (const not_trace_rule &ntr)
        {
            if (this->way_matching != ntr.way_matching)return this->way_matching < ntr.way_matching;
            return this->str < ntr.str;
        }

        friend bool operator< (const not_trace_rule &ntr1, const not_trace_rule &ntr2)
        {
            if (ntr1.way_matching != ntr2.way_matching)return ntr1.way_matching < ntr2.way_matching;
            return ntr1.str < ntr2.str;
        }

        friend bool operator== (const not_trace_rule &ntr1, const not_trace_rule &ntr2)
        {return ntr1.way_matching == ntr2.way_matching && ntr1.str == ntr2.str;}
        friend bool operator!= (const not_trace_rule &ntr1, const not_trace_rule &ntr2) { return !(ntr1 == ntr2); }
    };

    std::set<size_t> rules_not_trace_by_id {};
    std::set<size_t> except_not_trace_by_id {};

    std::set<not_trace_rule> rules_not_trace_by_name {};
    std::set<not_trace_rule> except_not_trace_by_name {};

    std::set<not_trace_rule> rules_not_trace_by_path {};
    std::set<not_trace_rule> except_not_trace_by_path {};

    #ifndef Module_one_func
private:
    void module_add_not_trace_help(std::set<not_trace_rule> &set, const std::string &name, E_StringWayMatching way_matching);
    void module_del_not_trace_help(std::set<not_trace_rule> &set, const std::string &name, E_StringWayMatching way_matching);
    #endif
public: 
    #ifndef Module_one_func
    void module_add_not_trace_rule_by_id(size_t id);
    /// <summary>if we traced the module or 
    /// if we do not trace the module with this id and there are no rules according to which this 
    /// module does not need to be traced then we will be traced it and return true; else return false;
    /// (if exist rule that don't allow tracing ths module try module_exc)</summary>
    void module_del_not_trace_rule_by_id(size_t id);
    /// <summary>create exception for trace module by id</summary>
    void module_add_not_trace_exception_by_id(size_t id);
    void module_del_not_trace_exception_by_id(size_t id);

    void module_add_not_trace_rule_by_name(const std::string &name, E_StringWayMatching way_matching);
    void module_del_not_trace_rule_by_name(const std::string &name, E_StringWayMatching way_matching);
    /// <summary>create exception for trace module by name</summary>
    void module_add_not_trace_exception_by_name(const std::string &name, E_StringWayMatching way_matching);
    void module_del_not_trace_exception_by_name(const std::string &name, E_StringWayMatching way_matching);

    void module_add_not_trace_rule_by_path(const std::string &path, E_StringWayMatching way_matching);
    void module_del_not_trace_rule_by_path(const std::string &path, E_StringWayMatching way_matching);
    /// <summary>create exception for trace module by path</summary>
    void module_add_not_trace_exception_by_path(const std::string &path, E_StringWayMatching way_matching);
    void module_del_not_trace_exception_by_path(const std::string &path, E_StringWayMatching way_matching);
    #endif
    #ifdef Module_one_func
    void change_traced_modules(E_ModuleRuleAction mr_act, E_ModuleRuleType mr_type, const ModuleRule &m_rule);
    #endif
private:
    /// <summary>upd state of trace for module with this id</summary>
    /// <returns>true if not traced, false in other way</returns>
    bool update_traced_module(size_t module_info_id);
    bool try_one_rule(const not_trace_rule &rule, size_t module_info_id, std::string &str, std::string &lowercase_str, E_ModuleRuleType upd_type);
    bool try_rules(const std::set<not_trace_rule> &set, size_t module_info_id, std::string &str, E_ModuleRuleType upd_type);
public:
    bool need_to_trace(size_t module_info_id);
    //size_t amount_traced_modules();
    //size_t amount_not_traced_modules();


private:
    //TODO:NEXT 2 LINES:I don't know how to make it wo static
    static void module_load_event(void *drcontext, const module_data_t *info, bool loaded);
    static void module_unload_event(void *drcontext, const module_data_t *info);

};



