#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <ctime>

class JsonReporter {
public:
    struct FlowInfo {
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        std::string app;
        std::string sni;
        uint64_t packets;
        bool blocked;
        std::vector<std::string> matched_patterns;
    };

    static void generate(
        const std::string& output_path,
        uint64_t total_packets,
        uint64_t forwarded,
        uint64_t dropped,
        const std::vector<std::pair<std::string,uint64_t>>& app_stats,
        const std::vector<FlowInfo>& flows
    ) {
        std::ofstream f(output_path);
        if (!f.is_open()) {
            fprintf(stderr, "[JSON] Failed to open file\n");
            return;
        }

        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", localtime(&t));

        f << "{\n";
        f << "  \"timestamp\": \"" << timebuf << "\",\n";
        f << "  \"summary\": {\n";
        f << "    \"total_packets\": " << total_packets << ",\n";
        f << "    \"forwarded\": " << forwarded << ",\n";
        f << "    \"dropped\": " << dropped << ",\n";
        f << "    \"active_flows\": " << flows.size() << "\n";
        f << "  },\n";

        f << "  \"app_breakdown\": {\n";
        for (size_t i = 0; i < app_stats.size(); i++) {
            f << "    \"" << app_stats[i].first << "\": " << app_stats[i].second;
            if (i + 1 < app_stats.size()) f << ",";
            f << "\n";
        }
        f << "  },\n";

        f << "  \"flows\": [\n";
        for (size_t i = 0; i < flows.size(); i++) {
            const auto& fl = flows[i];
            f << "    {\n";
            f << "      \"src_ip\": \"" << fl.src_ip << "\",\n";
            f << "      \"dst_ip\": \"" << fl.dst_ip << "\",\n";
            f << "      \"src_port\": " << fl.src_port << ",\n";
            f << "      \"dst_port\": " << fl.dst_port << ",\n";
            f << "      \"app\": \"" << fl.app << "\",\n";
            f << "      \"sni\": \"" << fl.sni << "\",\n";
            f << "      \"packets\": " << fl.packets << ",\n";
            f << "      \"blocked\": " << (fl.blocked ? "true" : "false") << "\n";
            f << "      \"matched_patterns\": [";
            for (size_t j = 0; j < fl.matched_patterns.size(); j++) {
                f << "\"" << fl.matched_patterns[j] << "\"";
                if (j + 1 < fl.matched_patterns.size()) f << ", ";
            }
            f << "]\n";
            f << "    }";
            if (i + 1 < flows.size()) f << ",";
            f << "\n";
        }
        f << "  ]\n";
        f << "}\n";

        printf("[JSON] Report saved to: %s\n", output_path.c_str());
    }
};
