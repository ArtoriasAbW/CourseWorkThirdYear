#include "general_headers.h"

//cpp:
#include <vector>
#include <string>
#include <set>

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


enum class StringWayMatching
{
    equal,
    equal_case_insensitive,
    contain,
    contain_case_insensitive,
};

struct modules_info
{
private:
    file_t module_info_file;
    std::vector<__module_info> modules;//MAYBE:<module_info *>   |   now, while we have only 4 fields so ptr is needless  
                                       //MAYBE: Dictionary<app_pc start, module_info> and find addr between two keys: (key_1 <= pc < key_2) & (pc<=m[key_1].end) => pc in module
    
    /// after  "module_info m_info = m_info_2;"  m_info_2 become invalid;
    /// not valid  =>  don't close module_info_file; don't dr_free_module_data; etc.
    bool valid;
public:
    modules_info() : module_info_file(0), valid(false), trace_blacklist(), rules_not_trace_by_name(), rules_not_trace_by_path() {};
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
    std::set<size_t> trace_blacklist;

    struct not_trace_rule
    {
        std::string str;
        std::string lowercase_str;
        StringWayMatching way_matching;
    };
    std::vector<not_trace_rule> rules_not_trace_by_name;
    std::vector<not_trace_rule> rules_not_trace_by_path;
public: 
    void module_add_not_trace_by_id(size_t id);
    size_t module_add_not_trace_by_name(const std::string &name, StringWayMatching way_matching);
    size_t module_add_not_trace_by_path(const std::string &path, StringWayMatching way_matching);
private:
    bool not_trace_rules_on(size_t module_info_id);
    bool try_one_rule(const not_trace_rule &rule, size_t module_info_id, const char *str, std::string &lowercase_str, bool with_insert = true);
    bool try_rules(const std::vector<not_trace_rule> &rules_not_trace, size_t module_info_id, const char *str, bool with_insert = true);
public:
    bool need_to_trace(size_t module_info_id);


private:
    //TODO:NEXT 2 LINES:I don't know how to make it wo static
    static void module_load_event(void *drcontext, const module_data_t *info, bool loaded);
    static void module_unload_event(void *drcontext, const module_data_t *info);

};



