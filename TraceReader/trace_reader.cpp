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
    input.close();
    return 0;
}