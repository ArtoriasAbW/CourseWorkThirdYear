#include "../format.pb.h"
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Need to specify tracefile" << std::endl;
        return 1;
    }
    std::ifstream input(argv[1]);
    TraceFormat::Trace trace;
    trace.ParseFromIstream(&input);
    std::cout << trace.header().memory_trace() << std::endl;
    std::cout << trace.header().num_of_reg() << std::endl;
    std::cout << trace.data().size() << std::endl;
    std::cout << trace.data(0).bbhdr().module_id() << std::endl;
    std::cout << trace.data(0).bbhdr().thread_id() << std::endl;
    // std::cout << trace.data(1).records().size() << std::endl;
    std::cout << "Instructions:" << std::endl;
    for (int i = 0; i < trace.data(1).records().size(); ++i) {
        std::cout << trace.data(1).records(i).insruction().opcode() << std::endl;
    }
    // std::cout << trace.data(1).records(1).insruction().opcode() << std::endl;
    // std::cout << trace.data(1).records(1).insruction().instr_address() << std::endl;
    // std::cout << trace.data(1).records(1).insruction().refs().size() << std::endl;
    input.close();
    return 0;
}