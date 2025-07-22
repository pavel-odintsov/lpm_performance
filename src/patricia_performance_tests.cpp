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

#include <boost/algorithm/string.hpp>

#include "lpm.h"

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


// Safe way to convert string to any integer
bool convert_string_to_any_integer_safe(const std::string& line, int& value) {
    int temp_value = 0;

    try {
        temp_value = std::stoi(line);
    } catch (...) {
        // Could not parse number correctly
        return false;
    }

    value = temp_value;

    return true;
}


class subnet_cidr_mask_t {
    public:
    subnet_cidr_mask_t() {
        this->subnet_address     = 0;
        this->cidr_prefix_length = 0;
    }
    subnet_cidr_mask_t(uint32_t subnet_address, uint32_t cidr_prefix_length) {
        this->subnet_address     = subnet_address;
        this->cidr_prefix_length = cidr_prefix_length;
    }

    // Big endian (network byte order)
    uint32_t subnet_address = 0;

    // Little endian
    uint32_t cidr_prefix_length = 0;

};

// Converts IP address in cidr form 11.22.33.44/24 to our representation
bool convert_subnet_from_string_to_binary_with_cidr_format_safe(const std::string& subnet_cidr, subnet_cidr_mask_t& subnet_cidr_mask) {
    if (subnet_cidr.empty()) {
        return false;
    }

    std::vector<std::string> subnet_as_string;

    split(subnet_as_string, subnet_cidr, boost::is_any_of("/"), boost::token_compress_on);

    if (subnet_as_string.size() != 2) {
        return false;
    }

    uint32_t subnet_as_int = 0;

    bool ip_to_integer_convresion_result = convert_ip_as_string_to_uint_safe(subnet_as_string[0], subnet_as_int);

    if (!ip_to_integer_convresion_result) {
        return false;
    }

    int cidr = 0;

    bool ip_conversion_result = convert_string_to_any_integer_safe(subnet_as_string[1], cidr);

    if (!ip_conversion_result) {
        return false;
    }

    subnet_cidr_mask = subnet_cidr_mask_t(subnet_as_int, cidr);

    return true;
}


int main() {
    lpm_trie_t *lookup_tree = lpm_create(LPM_IPV4_MAX_DEPTH);

    std::string line;
    std::ifstream myfile("cable_isp_prefixes.txt");

    if (!myfile.is_open()) {
        std::cerr << "Could not open file with prefix list" << std::endl;
        return 1;
    }

    std::cout << "Start subnet load to patricia" << std::endl;
    while (getline(myfile, line)) {
        subnet_cidr_mask_t prefix{};

        if (!convert_subnet_from_string_to_binary_with_cidr_format_safe(line, prefix)) {
            std::cerr << "Cannot parse " << line << " as prefix" << std::endl;
            continue;
        }   

        std::cout << "Prefix length: " << prefix.cidr_prefix_length << std::endl;

        uint8_t* ip_as_bytes = (uint8_t*)&prefix.subnet_address;

        // 10 is random next hop
        lpm_add(lookup_tree, ip_as_bytes, prefix.cidr_prefix_length, 10);
    }

    std::cout << "Finished subnet load to patricia" << std::endl;

    // Load example traffic
    std::ifstream example_traffic("cable_isp_traffic.json");

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

    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    uint64_t number_of_reruns = 100000;

    // I do not multiple by two here becasue we assume that interation involves two lookups all the time
    unsigned long total_ops = number_of_reruns * vector_of_packets.size();

    uint64_t match_source = 0;
    uint64_t match_destination = 0;

    for (int j = 0; j < number_of_reruns; j++) {
        for (const auto& pair: vector_of_packets) {
            uint8_t* ip_as_bytes = (uint8_t*)&pair.first;

            auto next_hop = lpm_lookup(lookup_tree, ip_as_bytes);

            if (next_hop != 0) {
                match_source++;
            }

            // Repeat for another IP
            uint8_t* ip_as_bytes_another = (uint8_t*)&pair.second;

            next_hop = lpm_lookup(lookup_tree, ip_as_bytes_another);

            if (next_hop != 0) {
                match_destination++;
            }
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    std::cout << "match_source: " << match_source << " match_destination: " << match_destination << std::endl;

    unsigned long used_seconds     = finish_time.tv_sec - start_time.tv_sec;
    unsigned long used_nanoseconds = finish_time.tv_nsec - start_time.tv_nsec;

    unsigned long total_used_nanoseconds = used_seconds * 1000000000 + used_nanoseconds;

    float megaops_per_second = (float)total_ops / ((float)total_used_nanoseconds / (float)1000000000) / 1000000;

    printf("Total time is %d seconds total ops: %d\nMillion of ops per second: "
           "%.1f\n",
           used_seconds, total_ops, megaops_per_second);

    lpm_destroy(lookup_tree);
}
