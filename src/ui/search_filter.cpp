#include "ui/search_filter.h"
#include "core/utils.h"
#include <algorithm>
#include <cctype>

void SearchFilter::Append(char c) {
    if (query_.length() < 32) {
        query_ += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
}

void SearchFilter::Pop() {
    if (!query_.empty()) {
        query_.pop_back();
    }
}

void SearchFilter::Clear() {
    query_.clear();
}

bool SearchFilter::Matches(const std::string& target) const {
    if (query_.empty()) return true;
    std::string lowerTarget = target;
    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lowerTarget.find(query_) != std::string::npos;
}

bool SearchFilter::Matches(unsigned long num) const {
    if (query_.empty()) return true;
    std::string numStr = std::to_string(num);
    return numStr.find(query_) != std::string::npos;
}

std::string SearchFilter::FormatBar(int width, int matchCount, int totalCount) const {
    std::string displayQuery = query_ + "_";
    char countBuf[64];
    std::snprintf(countBuf, sizeof(countBuf), "(%d/%d matches)", matchCount, totalCount);

    std::string content = " Filter: [ " + displayQuery;
    if (content.length() < 35) {
        content.append(35 - content.length(), ' ');
    }
    content += " ] " + std::string(countBuf);
    if (!query_.empty()) {
        content += " [Esc: Clear Filter]";
    } else {
        content += " [Type to Filter]";
    }

    return "\x1b[97;44m" + PadOrTrim(content, width - 1) + "\x1b[0m\n";
}
