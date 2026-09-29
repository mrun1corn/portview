#pragma once

#include <string>

class SearchFilter {
public:
    SearchFilter() = default;

    bool IsEmpty() const { return query_.empty(); }
    const std::string& GetQuery() const { return query_; }
    void Append(char c);
    void Pop();
    void Clear();

    bool Matches(const std::string& target) const;
    bool Matches(unsigned long num) const;
    bool Matches(unsigned int num) const { return Matches(static_cast<unsigned long>(num)); }
    bool Matches(unsigned short num) const { return Matches(static_cast<unsigned long>(num)); }

    std::string FormatBar(int width, int matchCount, int totalCount) const;

private:
    std::string query_;
};
