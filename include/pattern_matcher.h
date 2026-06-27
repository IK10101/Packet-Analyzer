#pragma once
#include <string>
#include <vector>
#include <regex>
#include <algorithm>

class PatternMatcher {
public:
    void addPattern(const std::string& pattern) {
        patterns_.push_back(pattern);
        regexes_.push_back(std::regex(pattern, std::regex::icase));
    }

    bool hasPatterns() const {
        return !patterns_.empty();
    }

    struct MatchResult {
        bool matched = false;
        std::vector<std::string> matched_patterns;
    };

    MatchResult scan(const uint8_t* payload, size_t len) const {
        if (patterns_.empty() || len == 0) return {};

        std::string text(reinterpret_cast<const char*>(payload), len);
        MatchResult result;

        for (size_t i = 0; i < regexes_.size(); i++) {
            if (std::regex_search(text, regexes_[i])) {
                result.matched = true;
                result.matched_patterns.push_back(patterns_[i]);
            }
        }
        return result;
    }

private:
    std::vector<std::string> patterns_;
    std::vector<std::regex> regexes_;
};
