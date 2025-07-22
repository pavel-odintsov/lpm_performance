#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <math.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "nlohmann/json.hpp"

#include "libpatricia/patricia.hpp"

using json = nlohmann::json;

#ifdef _WIN32
// We have no inet_aton on Windows but we do have inet_pton https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inet_pton
// Convert IP in string representation to uint32_t in big endian (network byte order)
// I think we can switch to using pton for Linux and other *nix too but we need to do careful testing including performance evaluation before
bool convert_ip_as_string_to_uint_safe(const std::string& ip, uint32_t& ip_as_integer) {
    struct in_addr ip_addr;
    
    // Both Windows and Linux return 1 in case of success
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) {
        return false;
    }

    // in network byte order
    ip_as_integer = ip_addr.s_addr;
    return true;
}
#else
// Convert IP in string representation to uint32_t in big endian (network byte order)
bool convert_ip_as_string_to_uint_safe(const std::string& ip, uint32_t& ip_as_integer) {
    struct in_addr ip_addr;

    // Please be careful! This function uses pretty strange approach for returned codes
    // inet_aton() returns nonzero if the address is valid, zero if not.
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
        return false; 
    }
    
    // in network byte order
    ip_as_integer = ip_addr.s_addr;
    return true;
}
#endif


int main() {
    patricia_tree_t* lookup_tree;
    lookup_tree = New_Patricia(32);

    std::string line;
    std::ifstream myfile("isp_prefixes.txt");

    if (!myfile.is_open()) {
        std::cerr << "Could not open file with prefix list" << std::endl;
        return 1;
    }

    std::cout << "Start subnet load to patricia" << std::endl;
    while (getline(myfile, line)) {
        make_and_lookup(lookup_tree, (char*)line.c_str());
    }

    std::cout << "Finished subnet load to patricia" << std::endl;

    // Load example traffic
    std::ifstream example_traffic("real_traffic.json");

    if (!example_traffic.is_open()) {
        std::cerr << "Could not open file with example traffic" << std::endl;
        return 1;
    }

    std::vector<std::pair<uint32_t, uint32_t>> fragmented_vector_of_packets;

    std::cout << "Start loading traffic into memory" << std::endl;

    while (getline(example_traffic, line)) {
        auto json_conf = json::parse(line, nullptr, false);

        if (json_conf.is_discarded()) {
            std::cerr << "Could not parse JSON: " << line << std::endl; 
            return 1;
        }

        // We test only IPv4 for now
        if (json_conf["ip_version"].get<std::string>() != "ipv4") {
            continue;
        }

        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;

        bool source_res = convert_ip_as_string_to_uint_safe(json_conf["source_ip"].get<std::string>(), src_ip);

        if (!source_res) {
            std::cout << "Cannot parse src ip" << std::endl;
            continue;
        }

        bool destionation_res = convert_ip_as_string_to_uint_safe(json_conf["destination_ip"].get<std::string>(), dst_ip);

        if (!destionation_res) {
            std::cout << "Cannot parse dst ip" << std::endl;
            continue;
        }
    
        fragmented_vector_of_packets.push_back(std::make_pair(src_ip, dst_ip));
    }

    std::cout << "Loaded traffic into memory" << std::endl;

    std::cout << "Defragment memory for input packet set" << std::endl;

    // Copy traffic into single continious memory regiuon to avoid issues performance issues due to memory frragmentation
    std::vector<std::pair<uint32_t, uint32_t>> vector_of_packets;
    vector_of_packets.reserve(fragmented_vector_of_packets.size());

    for (const auto& pair: fragmented_vector_of_packets) {
        vector_of_packets.push_back(pair);
    }

    fragmented_vector_of_packets.clear();

    std::cout << "Defragmentation done" << std::endl;

    std::cout << "I have " << vector_of_packets.size() << " real packets for test" << std::endl;

    std::cout << "Start tests" << std::endl;

    // Process vector_of_packets

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.family     = AF_INET;
    prefix_for_check_adreess.bitlen     = 32;
    // prefix_for_check_adreess.add.sin.s_addr = 123123123;

    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    uint64_t number_of_reruns = 100000;

    // I do not multiple by two here becasue we assume that interation involves two lookups all the time
    unsigned long total_ops = number_of_reruns * vector_of_packets.size();

    uint64_t match_source = 0;
    uint64_t match_destionation = 0;

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& pair: vector_of_packets) {
            prefix_for_check_adreess.add.sin.s_addr = pair.first;

            patricia_node_t* found_patrica_node     = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

            if (found_patrica_node != NULL) {
                match_source++;
            }

            // Repeat for another IP
            prefix_for_check_adreess.add.sin.s_addr = pair.second;

            found_patrica_node     = patricia_search_best2(lookup_tree, &prefix_for_check_adreess, 1);

            if (found_patrica_node != NULL) {
                match_destionation++;
            }
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    std::cout << "match_source: " << match_source << " match_destionation: " << match_destionation << std::endl;

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    printf("Total time is %d seconds total ops: %d\nMillion of ops per second: "
           "%.1f\n",
           used_seconds, total_ops, megaops_per_second);

    Destroy_Patricia(lookup_tree, [](void* ptr) {});
}
