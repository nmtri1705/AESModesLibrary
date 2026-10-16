#include "aes_modes.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
using namespace aes_modes;
Bytes field(const std::string& s) { return s == "-" ? Bytes{} : from_hex(s); }
int main(int argc, char** argv) {
 try {
  std::ifstream f(argc > 1 ? argv[1] : "tests/modes_vectors.txt");
  if (!f) throw std::runtime_error("Cannot open vectors");
  std::string line; int count=0, rejected=0;
  while (std::getline(f,line)) {
   std::istringstream s(line); std::string n,k,p,v,a,c; int param;
   if (!(s>>n>>k>>p>>v>>a>>param>>c)) throw std::runtime_error("Bad vector");
   auto key=field(k), plain=field(p), iv=field(v), aad=field(a), expected=field(c);
   if (transform(n,true,key,plain,iv,aad,param)!=expected) throw std::runtime_error(n+" encrypt mismatch");
   auto result=transform(n,false,key,expected,iv,n=="gmac"?plain:aad,param);
   if (result!=(n=="gmac"?Bytes{}:plain)) throw std::runtime_error(n+" decrypt mismatch");
   if(n=="gcm" || n=="ccm" || n=="gcm-siv" || n=="gmac" || n=="kw" || n=="kwp") {
    auto bad=expected; bad.back()^=1; bool caught=false;
    try { transform(n,false,key,bad,iv,n=="gmac"?plain:aad,param); }
    catch(const std::exception&) { caught=true; }
    if(!caught) throw std::runtime_error(n+" accepted tampering");
    ++rejected;
   }
   ++count;
   std::string label = n;
   if (label == "ecb-raw") label = "ecb";
   if (label == "cbc-raw") label = "cbc";
   std::transform(label.begin(), label.end(), label.begin(),
                  [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
   if (n == "cfb") label += std::to_string(param == 0 ? 128 : param);
   std::cout << "PASS " << label << " AES-" << key.size() * 8
             << " (encrypt + " << (n == "gmac" ? "verify" : "decrypt")
             << ") [vector " << count << "]\n";
  }
  if(!count) throw std::runtime_error("Empty vectors");
  std::cout<<"ALL "<<count<<" VECTORS PASS; "<<rejected<<" tamper rejection cases\n";
 } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
