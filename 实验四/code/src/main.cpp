#include "header.h"

void print_h(int argc, char *argv[]) {
    if (2 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::cout << "MD5：usage:\n" << "\t" << "[-h] --help information " << std::endl;
    std::cout << "\t" << "[-c] --TCP connect scan" << std::endl;
    std::cout << "\t" << "[-s] --TCP syn scan" << std::endl;
    std::cout << "\t" << "[-f] --TCP fin scan" << std::endl;
    std::cout << "\t" << "[-u] --UDP scan" << std::endl;
}



void print_t(int argc, char *argv[]) {
    if (2 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::string test[] = {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};
    MD5 md5;
    for (int i = 0; i < 7; ++i) { 
        md5.Update((const BYTE*)test[i].c_str(), test[i].length());
        std::cout << "MD5(\"" + test[i] + "\") = " << md5.Tostring()<< std::endl;
    }
}

void print_c(int argc, char *argv[]) {
    if (3 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::string filePath = argv[2];
    std::ifstream fileStream(filePath);
    MD5 md5;
    md5.Update(fileStream);
    std::cout << "The MD5 value of file(\"" << filePath << "\") is " << md5.Tostring() << std::endl;
}

void print_v(int argc,char *argv[]) {
    if (3 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::string filePath = argv[2];
    std::cout << "Please input the MD5 value of file(\"" << filePath << "\")..." << std::endl;
    std::string inputMD5;
    std::cin >> inputMD5;
    std::cout << "The old MD5 value of file(\"" << filePath << "\") you have input is" << std::endl << inputMD5 << std::endl;
    std::ifstream fileStream(filePath);
    MD5 md5;
    md5.Update(fileStream);
    std::string genMD5 = md5.Tostring();
    std::cout << "The new MD5 value of file(\"" << filePath << "\") that has computed is" << std::endl << genMD5 << std::endl;
    if (!genMD5.compare(inputMD5)) {
        std::cout << "OK! The file is integrated" << std::endl;
    }
    else {
        std::cout << "Match Error! The file has been modified!" << std::endl;
    }
}

void print_f(int argc, char *argv[]) {
    if (4 != argc) {
        std::cout << "参数错误." << std::endl;
        return;
    }
    std::string filePath = argv[2];
    std::string md5Path = argv[3];
    std::ifstream md5Stream(md5Path);
    std::string oldMD5Str((std::istreambuf_iterator<char>(md5Stream)), std::istreambuf_iterator<char>());
    oldMD5Str = (std::string)strtok(const_cast<char*>(oldMD5Str.c_str())," ");
    std::cout << "The old MD5 value of file(\"" << filePath << "\") in " << md5Path << " is " << std::endl << oldMD5Str << std::endl;
    std::ifstream fileStream(filePath);
    MD5 md5;
    md5.Update(fileStream);
    std::string genMD5 = md5.Tostring();
    std::cout << "The new MD5 value of file(\"" << filePath << "\") that has computed is" << std::endl << genMD5 << std::endl;
    if (!genMD5.compare(oldMD5Str)) {
        std::cout << "OK! The file is integrated" << std::endl;
    }
    else {
        std::cout << "Match Error! The file has been modified!" << std::endl;
    }
}

int main(int argc,char *argv[]) { 
    std::unordered_map<std::string, void(*)(int, char*[])> mapOp = {{"-t", print_t}, {"-h", print_h}, {"-c", print_c}, {"-v", print_v}, {"-f", print_f}};
    if (argc < 2) { 
        std::cout << "参数错误，argc = " << argc << std::endl;
        return -1;
    }
    std::string op = argv[1];
    if (mapOp.find(op) != mapOp.end()) {
        mapOp[op](argc, argv);
    }
    return 0;
}