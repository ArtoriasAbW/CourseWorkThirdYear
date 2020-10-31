#include "general_headers.h"

//cpp:
#include <vector>
//#include <map>

/*
#include <functional>
using namespace std::placeholders;
#include <utility> // TODO:DEL
*/

typedef struct __module_info//TODO:C++
{
    uint id; //module_info valid only if (id != 0)
    app_pc start;
    app_pc end;
    module_data_t *m_data;//only for dr_module_contain_addr, as may not be contiguous
    __module_info() : id(0), start(0), end(0), m_data(NULL) {}
    __module_info(uint _id, app_pc _start, app_pc _end, module_data_t *ptr) : id(_id), start(_start), end(_end), m_data(ptr) {}
}__module_info;

struct modules_info
{
public:
    file_t module_info_file;
    std::vector<__module_info> modules;//MAYBE:<module_info *>   |   now, while we have only 4 fields so ptr is needless  
                                       //MAYBE: Dictionary<app_pc start, module_info> and find addr between two keys: (key_1 <= pc < key_2) & (pc<=m[key_1].end) => pc in module
private:
    bool valid;
public:
    modules_info() : module_info_file(NULL), valid(false) {};
    modules_info(const char *file_name);
    modules_info &operator= (modules_info &&other) noexcept;

    ~modules_info();
    bool mi_free();
    
    app_pc get_module_start(size_t index);
    bool check_ptr_in_module(app_pc ptr, size_t index);
    size_t get_module_id(app_pc ptr);

private:
    //TODO:NEXT 2 LINES:I don't know how to make it wo static
    static void module_load_event(void *drcontext, const module_data_t *info, bool loaded);
    static void module_unload_event(void *drcontext, const module_data_t *info);

};



