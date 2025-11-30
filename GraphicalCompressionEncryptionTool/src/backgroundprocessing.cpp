// ========== 项目头文件 ==========
#include "backgroundprocessing.h"

// ========== GTK/GLib 头文件 ==========
#include <glibmm/spawn.h>
#include <glibmm/main.h>

// OpenSSL资源包装器
struct EVP_CIPHER_CTX_Deleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

struct BIO_Deleter {
    void operator()(BIO *bio) const {
        if (bio) {
            BIO_free_all(bio);
        }
    }
};

using BioPtr = std::unique_ptr<BIO, BIO_Deleter>;

// ========== 构造函数和析构函数 ==========

BackgroundProcessing::BackgroundProcessing(CompletionCallback completion_callback,ProgressCallback progress_callback,EncryptionCallback encryption_callback,FilenameFixCallback filename_fix_callback)
    : m_completion_callback(completion_callback),m_progress_callback(progress_callback),m_encryption_callback(encryption_callback),m_filename_fix_callback(filename_fix_callback),m_cancelled(false) {
    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

BackgroundProcessing::~BackgroundProcessing() {
    cancel_operation();
    if (m_worker_thread && m_worker_thread->joinable()) {
        m_worker_thread->join();
    }
    // 清理OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

// ========== 压缩解压操作函数 ==========

void BackgroundProcessing::compress_with_rar(const std::string &command, const std::string &output_path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command, output_path]() { 
        process_rar_compression(command, output_path); 
    });
}

void BackgroundProcessing::compress_with_7z(const std::string &command, [[maybe_unused]] const std::string &output_path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() { 
        process_7z_compression(command); 
    });
}

void BackgroundProcessing::extract_with_rar(const std::string &command, [[maybe_unused]] const std::string &archive_path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        std::string result = execute_command(command);
        send_completion_signal(result, true); 
    });
}

void BackgroundProcessing::extract_with_7z(const std::string &command, [[maybe_unused]] const std::string &archive_path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        std::string result = execute_command(command);
        send_completion_signal(result, true); 
    });
}

void BackgroundProcessing::extract_with_unzip(const std::string &command, [[maybe_unused]] const std::string &archive_path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        process_unzip_extraction(command);
    });
}

void BackgroundProcessing::list_archive_contents(const std::string &command, [[maybe_unused]] const std::string &tool) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        std::string result = execute_command(command);
        send_completion_signal(result, true); 
    });
}

void BackgroundProcessing::test_archive_integrity(const std::string &command, [[maybe_unused]] const std::string &tool) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        std::string result = execute_command(command);
        send_completion_signal(result, true); 
    });
}

void BackgroundProcessing::get_archive_comment(const std::string &command, [[maybe_unused]] const std::string &tool) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, command]() {
        std::string result = execute_command(command);
        send_completion_signal(result, true); 
    });
}

// ========== 文本加密解密操作函数 ==========

void BackgroundProcessing::encrypt_text(const std::string &plaintext, const std::string &password,
                                        const std::string &cipher_mode, const std::string &kdf) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, plaintext, password, cipher_mode, kdf]() { 
        process_text_encryption(plaintext, password, cipher_mode, kdf); 
    });
}

void BackgroundProcessing::decrypt_text(const std::string &ciphertext, const std::string &password,
                                        const std::string &cipher_mode, const std::string &kdf) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, ciphertext, password, cipher_mode, kdf]() { 
        process_text_decryption(ciphertext, password, cipher_mode, kdf); 
    });
}

// ========== 文件名修复操作函数 ==========

void BackgroundProcessing::fix_filenames_encoding(const std::string &path) {
    cancel_operation();
    m_cancelled = false;
    m_worker_thread = std::make_unique<std::thread>([this, path]() { 
        process_filename_fix(path); 
    });
}

void BackgroundProcessing::cancel_operation() {
    m_cancelled = true;
    if (m_worker_thread && m_worker_thread->joinable()) {
        m_worker_thread->join();
    }
}

// ========== 压缩解压处理函数 ==========

void BackgroundProcessing::process_rar_compression(const std::string &command, const std::string &output_path) {
    std::string result = execute_command(command);
    cleanup_comment_file(output_path);
    bool success = true;
    if (result.find("错误") != std::string::npos ||
        result.find("Error") != std::string::npos ||
        result.find("failed") != std::string::npos) {
        success = false;
    }
    send_completion_signal(result, success);
}

void BackgroundProcessing::process_7z_compression(const std::string &command) {
    std::string result = execute_command(command);
    bool success = true;
    if (result.find("错误") != std::string::npos ||
        result.find("Error") != std::string::npos ||
        result.find("failed") != std::string::npos) {
        success = false;
    }
    send_completion_signal(result, success);
}

void BackgroundProcessing::process_unzip_extraction(const std::string &command) {
    std::string result = execute_command(command);
    bool success = true;
    if (result.find("错误") != std::string::npos ||
        result.find("Error") != std::string::npos ||
        result.find("failed") != std::string::npos ||
        result.find("incorrect password") != std::string::npos) {
        success = false;
    }
    send_completion_signal(result, success);
}

inline std::string BackgroundProcessing::check_command_result(int exit_status, const std::string &output, const std::string &error) {
    std::stringstream result;
    if (exit_status == 0) {
        result << "命令执行成功\n";
    } else {
        result << "命令执行失败，退出状态: " << exit_status << "\n";
    }
    if (!output.empty()) {
        result << "输出:\n" << output << "\n";
    }
    if (!error.empty()){
        result << "错误信息:\n" << error << "\n";
    }
    return result.str();
}

// ========== 文本加密解密处理函数 ==========

void BackgroundProcessing::process_text_encryption(const std::string &plaintext, const std::string &password,const std::string &cipher_mode, const std::string &kdf) {
    if (password.empty()) {
        send_encryption_signal("错误: 密码不能为空", false, true);
        return;
    }
    try{
        std::string encrypted_result = perform_encryption(plaintext, password, cipher_mode, kdf);
        send_progress_signal("文本加密完成");
        send_encryption_signal(encrypted_result, true, true);
    } catch (const std::exception &e) {
        std::string error_msg = std::string("加密失败: ") + e.what();
        send_progress_signal(error_msg);
        send_encryption_signal(error_msg, false, true);
    }
}

void BackgroundProcessing::process_text_decryption(const std::string &ciphertext, const std::string &password,const std::string &cipher_mode, const std::string &kdf) {
    if (password.empty()) {
        send_encryption_signal("错误: 密码不能为空", false, false);
        return;
    }
    try {
        std::string decrypted_result = perform_decryption(ciphertext, password, cipher_mode, kdf);
        send_progress_signal("文本解密完成");
        send_encryption_signal(decrypted_result, true, false);
    } catch (const std::exception &e) {
        std::string error_msg = std::string("解密失败: ") + e.what();
        send_progress_signal(error_msg);
        send_encryption_signal(error_msg, false, false);
    }
}

// ========== 文件名修复处理函数 ==========

void BackgroundProcessing::process_filename_fix(const std::string &path) {
    send_progress_signal("文件名乱码修复中...");
    try {
        std::string result;
        if (!std::filesystem::exists(path)) {
            send_filename_fix_signal("错误: 路径不存在: " + path, false);
            return;
        }
        if (std::filesystem::is_directory(path)) {
            result = fix_directory_filenames(path);
        } else {
            std::filesystem::path file_path(path);
            std::string parent_path = file_path.parent_path().string();
            std::string old_filename = file_path.filename().string();
            std::string new_filename = fix_filename_encoding(old_filename);
            
            if (new_filename != old_filename) {
                std::filesystem::path new_path = std::filesystem::path(parent_path) / new_filename;
                std::filesystem::rename(file_path, new_path);
                
                std::string safe_old, safe_new = new_filename;
                std::string ext = file_path.extension().string();
                safe_old = "{可能乱码文件名安全屏蔽}" + ext;
                
                result = "修复: \"" + safe_old + "\" -> \"" + safe_new + "\"";
            } else {
                result = "文件名已经是有效的UTF-8编码: " + old_filename;
            }
        }
        send_filename_fix_signal(result, true);
    } catch (const std::exception &e) {
        std::string error_msg = std::string("文件名修复失败: ") + e.what();
        send_progress_signal(error_msg);
        send_filename_fix_signal(error_msg, false);
    }
}

std::string BackgroundProcessing::fix_filename_encoding(const std::string& filename) {
    if (filename.empty()) return filename;
    
    auto is_ascii = [](const std::string& str) -> bool {
        for (unsigned char c : str) {
            if (c > 0x7F) return false;
        }
        return true;
    };
    
    if (is_ascii(filename)) {
        return filename;
    }
    
    auto is_valid_utf8 = [](const std::string& str) -> bool {
        size_t i = 0;
        while (i < str.size()) {
            unsigned char c = static_cast<unsigned char>(str[i]);
            size_t remaining = str.size() - i;
            
            if (c <= 0x7F) {
                i++;
            } else if ((c & 0xE0) == 0xC0) {
                if (remaining < 2 || (static_cast<unsigned char>(str[i+1]) & 0xC0) != 0x80) 
                    return false;
                i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                if (remaining < 3 || 
                    (static_cast<unsigned char>(str[i+1]) & 0xC0) != 0x80 || 
                    (static_cast<unsigned char>(str[i+2]) & 0xC0) != 0x80) 
                    return false;
                i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                if (remaining < 4 || 
                    (static_cast<unsigned char>(str[i+1]) & 0xC0) != 0x80 || 
                    (static_cast<unsigned char>(str[i+2]) & 0xC0) != 0x80 || 
                    (static_cast<unsigned char>(str[i+3]) & 0xC0) != 0x80) 
                    return false;
                i += 4;
            } else {
                return false;
            }
        }
        return true;
    };
    
    auto detect_7z_mojibake = [](const std::string& str) -> bool {
        int pattern_count = 0;
        int total_3byte_sequences = 0;
        
        for (size_t i = 0; i < str.length(); ) {
            unsigned char c = static_cast<unsigned char>(str[i]);
            
            if (c <= 0x7F) {
                i++;
            } else if ((c & 0xE0) == 0xC0) {
                i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                total_3byte_sequences++;
                
                if (c == 0xEE && i + 2 < str.length()) {
                    unsigned char c1 = static_cast<unsigned char>(str[i+1]);
                    if (c1 == 0x82 || c1 == 0x83) {
                        pattern_count++;
                    }
                }
                i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                i += 4;
            } else {
                i++;
            }
        }
        
        return total_3byte_sequences > 2 && 
               (pattern_count * 100 / total_3byte_sequences) > 50;
    };
    
    auto repair_7z_mojibake_universal = [](const std::string& str) -> std::string {
        std::vector<unsigned char> byte_sequence;
        
        for (size_t i = 0; i < str.length(); ) {
            unsigned char c = static_cast<unsigned char>(str[i]);
            
            if (c <= 0x7F) {
                byte_sequence.push_back(c);
                i++;
            } else if ((c & 0xE0) == 0xC0) {
                byte_sequence.push_back(c);
                if (i + 1 < str.length()) {
                    byte_sequence.push_back(static_cast<unsigned char>(str[i+1]));
                }
                i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                if (c == 0xEE && i + 2 < str.length()) {
                    unsigned char c1 = static_cast<unsigned char>(str[i+1]);
                    unsigned char c2 = static_cast<unsigned char>(str[i+2]);
                    
                    if (c1 == 0x82 || c1 == 0x83) {
                        byte_sequence.push_back(c2);
                    } else {
                        byte_sequence.push_back(c);
                        byte_sequence.push_back(c1);
                        byte_sequence.push_back(c2);
                    }
                } else {
                    byte_sequence.push_back(c);
                    if (i + 1 < str.length()) byte_sequence.push_back(static_cast<unsigned char>(str[i+1]));
                    if (i + 2 < str.length()) byte_sequence.push_back(static_cast<unsigned char>(str[i+2]));
                }
                i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                for (size_t j = 0; j < 4 && i + j < str.length(); j++) {
                    byte_sequence.push_back(static_cast<unsigned char>(str[i+j]));
                }
                i += 4;
            } else {
                byte_sequence.push_back(c);
                i++;
            }
        }
        
        return std::string(byte_sequence.begin(), byte_sequence.end());
    };
    
    auto score_chinese_content = [is_valid_utf8](const std::string& utf8_str) -> int {
        if (!is_valid_utf8(utf8_str)) return 0;
        
        int total_non_ascii = 0;
        int chinese_chars = 0;
        int chinese_punctuation = 0;
        int suspicious_chars = 0;
        int private_use_chars = 0;
        
        static const std::vector<std::string> suspicious_patterns = {
            "锟", "绢", "斤", "拷", "�", "￾", "", "", "", "", "", "ȵ", 
            "", "", "", "", "", "", "ȵ", "Ĳ", "", "", "񱨸", ""
        };
        
        for (size_t i = 0; i < utf8_str.length(); ) {
            unsigned char c = static_cast<unsigned char>(utf8_str[i]);
            
            if (c <= 0x7F) {
                i++;
            } else if ((c & 0xE0) == 0xC0) {
                i += 2;
                total_non_ascii++;
            } else if ((c & 0xF0) == 0xE0) {
                if (i + 2 < utf8_str.length()) {
                    unsigned char c1 = c;
                    unsigned char c2 = static_cast<unsigned char>(utf8_str[i+1]);
                    unsigned char c3 = static_cast<unsigned char>(utf8_str[i+2]);
                    
                    uint32_t code_point = ((c1 & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
                    
                    if ((code_point >= 0x4E00 && code_point <= 0x9FFF) ||  
                        (code_point >= 0x3400 && code_point <= 0x4DBF) ||  
                        (code_point >= 0x20000 && code_point <= 0x2A6DF) || 
                        (code_point >= 0x2A700 && code_point <= 0x2B73F) || 
                        (code_point >= 0x2B740 && code_point <= 0x2B81F) || 
                        (code_point >= 0x2B820 && code_point <= 0x2CEAF)) { 
                        chinese_chars++;
                    }
                    else if ((code_point >= 0x3000 && code_point <= 0x303F) ||  
                             (code_point >= 0xFF00 && code_point <= 0xFFEF)) {  
                        chinese_punctuation++;
                    }
                    else if (code_point >= 0xE000 && code_point <= 0xF8FF) {
                        private_use_chars++;
                    }
                }
                i += 3;
                total_non_ascii++;
            } else if ((c & 0xF8) == 0xF0) {
                i += 4;
                total_non_ascii++;
            } else {
                i++;
            }
        }
        
        for (const auto& pattern : suspicious_patterns) {
            if (utf8_str.find(pattern) != std::string::npos) {
                suspicious_chars++;
            }
        }
        
        if (total_non_ascii == 0) return 0;
        
        int64_t base_score = static_cast<int64_t>(chinese_chars + chinese_punctuation) * 1000000 / total_non_ascii;
        
        int64_t penalty = 0;
        if (private_use_chars > 0) {
            penalty += static_cast<int64_t>(private_use_chars) * 450000;
        }
        if (suspicious_chars > 0) {
            penalty += static_cast<int64_t>(suspicious_chars) * 600000;
        }
        
        int64_t final_score = base_score - penalty;
        return static_cast<int>(std::max(static_cast<int64_t>(0), final_score));
    };
    
    if (is_valid_utf8(filename)) {
        int original_score = score_chinese_content(filename);
        if (original_score >= 600000) {
            return filename;
        }
    }
    
    static const std::vector<const char*> optimized_encodings = {
        "GB18030", "GBK", "CP936",      
        "BIG5", "BIG5-HKSCS", "CP950",  
        "EUC-CN", "EUC-TW"              
    };
    
    auto smart_encoding_fix = [&](const std::string& input, bool try_double_decode = false) -> std::pair<std::string, int> {
        int best_score = 0;
        std::string best_result;
        
        std::vector<std::string> sequences_to_try = {input};
        
        if (try_double_decode) {
            std::vector<const char*> intermediate_encodings = {"ISO-8859-1", "CP1252"};
            
            for (const char* intermediate : intermediate_encodings) {
                iconv_t cd_to_bytes = iconv_open(intermediate, "UTF-8");
                if (cd_to_bytes == (iconv_t)-1) continue;
                
                size_t in_bytes = input.size();
                size_t out_bytes = in_bytes;
                std::vector<char> in_buf(input.begin(), input.end());
                std::vector<char> out_buf(out_bytes);
                
                char* in_ptr = in_buf.data();
                char* out_ptr = out_buf.data();
                
                iconv(cd_to_bytes, nullptr, nullptr, nullptr, nullptr);
                
                if (iconv(cd_to_bytes, &in_ptr, &in_bytes, &out_ptr, &out_bytes) != (size_t)-1) {
                    iconv_close(cd_to_bytes);
                    
                    std::string byte_seq(out_buf.data(), out_ptr - out_buf.data());
                    sequences_to_try.push_back(byte_seq);
                } else {
                    iconv_close(cd_to_bytes);
                }
            }
            
            if (detect_7z_mojibake(input)) {
                std::string repaired = repair_7z_mojibake_universal(input);
                sequences_to_try.push_back(repaired);
            }
        }
        
        for (const auto& sequence : sequences_to_try) {
            for (const char* encoding : optimized_encodings) {
                iconv_t cd = iconv_open("UTF-8", encoding);
                if (cd == (iconv_t)-1) continue;
                
                size_t in_bytes = sequence.size();
                size_t out_bytes = in_bytes * 4;
                std::vector<char> in_buf(sequence.begin(), sequence.end());
                std::vector<char> out_buf(out_bytes);
                
                char* in_ptr = in_buf.data();
                char* out_ptr = out_buf.data();
                
                iconv(cd, nullptr, nullptr, nullptr, nullptr);
                
                if (iconv(cd, &in_ptr, &in_bytes, &out_ptr, &out_bytes) != (size_t)-1) {
                    iconv_close(cd);
                    
                    std::string result(out_buf.data(), out_ptr - out_buf.data());
                    if (is_valid_utf8(result)) {
                        int score = score_chinese_content(result);
                        if (score > best_score) {
                            best_score = score;
                            best_result = result;
                        }
                    }
                } else {
                    iconv_close(cd);
                }
            }
        }
        
        return {best_result, best_score};
    };
    
    if (is_valid_utf8(filename) && detect_7z_mojibake(filename)) {
        auto [result, score] = smart_encoding_fix(filename, true);
        if (score >= 300000) {
            return result;
        }
    }
    
    auto [best_result, best_score] = smart_encoding_fix(filename, false);
    
    if (best_score >= 400000) {
        return best_result;
    }
    
    if (!is_valid_utf8(filename) && best_score < 400000) {
        for (const char* encoding : optimized_encodings) {
            iconv_t cd = iconv_open("UTF-8//IGNORE", encoding);
            if (cd == (iconv_t)-1) continue;
            
            size_t in_bytes = filename.size();
            size_t out_bytes = in_bytes * 4;
            std::vector<char> in_buf(filename.begin(), filename.end());
            std::vector<char> out_buf(out_bytes);
            
            char* in_ptr = in_buf.data();
            char* out_ptr = out_buf.data();
            
            iconv(cd, nullptr, nullptr, nullptr, nullptr);
            
            if (iconv(cd, &in_ptr, &in_bytes, &out_ptr, &out_bytes) != (size_t)-1) {
                iconv_close(cd);
                
                std::string result(out_buf.data(), out_ptr - out_buf.data());
                if (is_valid_utf8(result)) {
                    int score = score_chinese_content(result);
                    if (score > best_score) {
                        best_score = score;
                        best_result = result;
                    }
                }
            } else {
                iconv_close(cd);
            }
        }
        
        if (best_score >= 300000) {
            return best_result;
        }
    }
    
    return filename;
}

std::string BackgroundProcessing::fix_directory_filenames(const std::string& directory_path) {
    int fixed_count = 0;
    int total_count = 0;
    
    std::filesystem::path dir_path(directory_path);
    std::string parent_path = dir_path.parent_path().string();
    std::string old_dir_name = dir_path.filename().string();
    std::string new_dir_name = fix_filename_encoding(old_dir_name);
    
    std::string current_directory_path = directory_path;
    
    if (new_dir_name != old_dir_name) {
        ++total_count;
        std::filesystem::path new_dir_path = std::filesystem::path(parent_path) / new_dir_name;
        try {
            std::filesystem::rename(dir_path, new_dir_path);
            fixed_count++;
            
            std::string safe_old = "{可能乱码目录名安全屏蔽}";
            std::string safe_new = new_dir_name;
            std::string fix_info = "修复目录: \"" + safe_old + "\" -> \"" + safe_new + "\"";
            send_progress_signal(fix_info);
            
            current_directory_path = new_dir_path.string();
        } catch (const std::exception& e) {
            std::string error_msg = "无法重命名目录: " + std::string(e.what());
            send_progress_signal(error_msg);
        }
    }
    
    std::queue<std::filesystem::path> dir_queue;
    dir_queue.push(current_directory_path);
    
    while (!dir_queue.empty() && !m_cancelled) {
        std::filesystem::path current_dir = dir_queue.front();
        dir_queue.pop();
        
        try {
            std::vector<std::filesystem::path> entries;
            
            for (const auto& entry : std::filesystem::directory_iterator(current_dir)) {
                if (m_cancelled) break;
                entries.push_back(entry.path());
            }
            
            for (const auto& entry_path : entries) {
                if (m_cancelled) break;
                
                total_count++;
                std::string old_name = entry_path.filename().string();
                std::string new_name = fix_filename_encoding(old_name);
                
                if (new_name != old_name) {
                    std::filesystem::path new_path = entry_path.parent_path() / new_name;
                    
                    try {
                        std::filesystem::rename(entry_path, new_path);
                        fixed_count++;
                        
                        std::string safe_old, safe_new = new_name;
                        if (std::filesystem::is_directory(entry_path)) {
                            safe_old = "{可能乱码目录名安全屏蔽}";
                        } else {
                            std::string ext = entry_path.extension().string();
                            safe_old = "{可能乱码文件名安全屏蔽}" + ext;
                        }
                        
                        std::string fix_info = "修复: \"" + safe_old + "\" -> \"" + safe_new + "\"";
                        send_progress_signal(fix_info);
                        
                        if (std::filesystem::is_directory(new_path)) {
                            dir_queue.push(new_path);
                        }
                    } catch (const std::exception& e) {
                        std::string error_msg = "无法重命名: " + entry_path.string() + " -> " + new_path.string() + ": " + e.what();
                        send_progress_signal(error_msg);
                    }
                } else {
                    if (std::filesystem::is_directory(entry_path)) {
                        dir_queue.push(entry_path);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::string error_msg = "处理目录时出错 " + current_dir.string() + ": " + e.what();
            send_progress_signal(error_msg);
        }
    }
    
    if (m_cancelled) {
        return "操作已取消，已修复 " + std::to_string(fixed_count) + " 个文件名";
    }
    
    return "文件名乱码修复共处理 " + std::to_string(total_count) + " 个文件/目录，修复 " + std::to_string(fixed_count) + " 个。";
}

// ========== 加密解密实现函数 ==========

std::string BackgroundProcessing::perform_encryption(const std::string &plaintext, const std::string &password,const std::string &cipher_mode, const std::string &kdf) {
    std::vector<unsigned char> salt = generate_salt(16);

    size_t key_length = 0;
    const EVP_CIPHER *cipher = nullptr;
    bool use_hmac = false;

    if (cipher_mode == "AES-256-GCM") {
        cipher = EVP_aes_256_gcm();
        key_length = 32;
        use_hmac = false;
    } else if (cipher_mode == "AES-256-CBC + HMAC") {
        cipher = EVP_aes_256_cbc();
        key_length = 32;
        use_hmac = true;
    } else {
        throw std::runtime_error("不支持的加密算法模式: " + cipher_mode);
    }

    int iterations = 320000;
    std::vector<unsigned char> derived_key = derive_key(password, salt, kdf, key_length * (use_hmac ? 2 : 1), iterations);

    std::vector<unsigned char> encryption_key(derived_key.begin(), derived_key.begin() + key_length);
    std::vector<unsigned char> hmac_key;
    if (use_hmac) {
        hmac_key.assign(derived_key.begin() + key_length, derived_key.end());
    }

    int iv_length = EVP_CIPHER_iv_length(cipher);
    std::vector<unsigned char> iv(static_cast<size_t>(iv_length));
    if (RAND_bytes(iv.data(), iv_length) != 1) {
        throw std::runtime_error("无法生成IV");
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("无法创建加密上下文");
    }

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, encryption_key.data(), iv.data()) != 1) {
        throw std::runtime_error("加密初始化失败");
    }

    if (cipher_mode == "AES-256-GCM") {
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + static_cast<size_t>(EVP_CIPHER_block_size(cipher)));
    int out_len = 0;
    int total_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                          reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("加密更新失败");
    }
    total_len = out_len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total_len, &out_len) != 1) {
        throw std::runtime_error("加密完成失败");
    }
    total_len += out_len;

    ciphertext.resize(static_cast<size_t>(total_len));

    std::vector<unsigned char> tag;
    if (cipher_mode == "AES-256-GCM") {
        tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            throw std::runtime_error("无法获取认证标签");
        }
    }

    std::vector<unsigned char> hmac;
    if (use_hmac) {
        std::vector<unsigned char> data_to_hmac;
        data_to_hmac.insert(data_to_hmac.end(), iv.begin(), iv.end());
        data_to_hmac.insert(data_to_hmac.end(), ciphertext.begin(), ciphertext.end());
        
        std::string hash_function = "SHA256";
        if (kdf.find("SHA3-256") != std::string::npos) {
            hash_function = "SHA3-256";
        } else if (kdf.find("BLAKE2S-256") != std::string::npos) {
            hash_function = "BLAKE2S-256";
        }
        
        hmac = compute_hmac(data_to_hmac, hmac_key, hash_function);
    }

    std::vector<unsigned char> final_data;
    final_data.insert(final_data.end(), salt.begin(), salt.end());
    final_data.insert(final_data.end(), iv.begin(), iv.end());
    final_data.insert(final_data.end(), ciphertext.begin(), ciphertext.end());

    if (cipher_mode == "AES-256-GCM") {
        final_data.insert(final_data.end(), tag.begin(), tag.end());
    } else if (use_hmac) {
        final_data.insert(final_data.end(), hmac.begin(), hmac.end());
    }

    return base64_encode(final_data);
}

std::string BackgroundProcessing::perform_decryption(const std::string &ciphertext_base64, const std::string &password,const std::string &cipher_mode, const std::string &kdf) {
    std::vector<unsigned char> final_data = base64_decode(ciphertext_base64);

    size_t salt_size = 16;
    size_t iv_size = 0;
    size_t tag_size = 0;
    size_t hmac_size = 0;
    bool use_hmac = false;

    if (cipher_mode == "AES-256-GCM") {
        iv_size = 12;
        tag_size = 16;
        use_hmac = false;
    } else if (cipher_mode == "AES-256-CBC + HMAC") {
        iv_size = 16;
        hmac_size = 32;
        use_hmac = true;
    }

    if (final_data.size() < salt_size + iv_size + (use_hmac ? hmac_size : tag_size)) {
        throw std::runtime_error("密文格式错误");
    }

    std::vector<unsigned char> salt(final_data.begin(), final_data.begin() + static_cast<ptrdiff_t>(salt_size));
    std::vector<unsigned char> iv(final_data.begin() + static_cast<ptrdiff_t>(salt_size),
                                  final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size));

    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> hmac;

    if (cipher_mode == "AES-256-GCM") {
        size_t ciphertext_size = final_data.size() - salt_size - iv_size - tag_size;
        encrypted_data.assign(final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size),
                              final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size + ciphertext_size));
        tag.assign(final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size + ciphertext_size), final_data.end());
    } else if (use_hmac) {
        size_t ciphertext_size = final_data.size() - salt_size - iv_size - hmac_size;
        encrypted_data.assign(final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size),
                              final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size + ciphertext_size));
        hmac.assign(final_data.begin() + static_cast<ptrdiff_t>(salt_size + iv_size + ciphertext_size), final_data.end());
    }

    if (use_hmac) {
        int iterations = 320000;
        size_t key_length = 32;
        std::vector<unsigned char> derived_key = derive_key(password, salt, kdf, key_length * 2, iterations);
        std::vector<unsigned char> encryption_key(derived_key.begin(), derived_key.begin() + key_length);
        std::vector<unsigned char> hmac_key(derived_key.begin() + key_length, derived_key.end());
        
        std::vector<unsigned char> data_to_verify;
        data_to_verify.insert(data_to_verify.end(), iv.begin(), iv.end());
        data_to_verify.insert(data_to_verify.end(), encrypted_data.begin(), encrypted_data.end());
        
        std::string hash_function = "SHA256";
        if (kdf.find("SHA3-256") != std::string::npos) {
            hash_function = "SHA3-256";
        } else if (kdf.find("BLAKE2S-256") != std::string::npos) {
            hash_function = "BLAKE2S-256";
        }
        
        if (!verify_hmac(data_to_verify, hmac, hmac_key, hash_function)) {
            throw std::runtime_error("HMAC验证失败 - 数据可能被篡改或密码错误");
        }
    }

    size_t key_length = 32;
    const EVP_CIPHER *cipher = nullptr;

    if (cipher_mode == "AES-256-GCM") {
        cipher = EVP_aes_256_gcm();
    } else if (cipher_mode == "AES-256-CBC + HMAC") {
        cipher = EVP_aes_256_cbc();
    } else {
        throw std::runtime_error("不支持的加密算法模式: " + cipher_mode);
    }

    int iterations = 320000;
    std::vector<unsigned char> key = derive_key(password, salt, kdf, key_length, iterations);

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("无法创建解密上下文");
    }

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("解密初始化失败");
    }

    if (cipher_mode == "AES-256-GCM") {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_size), tag.data()) != 1) {
            throw std::runtime_error("无法设置认证标签");
        }
    }

    std::vector<unsigned char> plaintext(encrypted_data.size() + static_cast<size_t>(EVP_CIPHER_block_size(cipher)));
    int out_len = 0;
    int total_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          encrypted_data.data(), static_cast<int>(encrypted_data.size())) != 1) {
        throw std::runtime_error("解密更新失败");
    }
    total_len = out_len;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total_len, &final_len) != 1) {
        throw std::runtime_error("解密完成失败 - 可能密码错误或数据被篡改");
    }
    total_len += final_len;

    plaintext.resize(static_cast<size_t>(total_len));

    return std::string(plaintext.begin(), plaintext.end());
}

// ========== 加密工具函数 ==========

inline std::vector<unsigned char> BackgroundProcessing::generate_salt(size_t size) {
    std::vector<unsigned char> salt(size);
    if (RAND_bytes(salt.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("无法生成随机盐值");
    }
    return salt;
}

std::vector<unsigned char> BackgroundProcessing::derive_key(const std::string &password,const std::vector<unsigned char> &salt,const std::string &kdf_function,size_t key_length,int iterations) {
    const EVP_MD *md = nullptr;
    
    if (kdf_function.find("Scrypt") != std::string::npos) {
        std::vector<unsigned char> key(key_length);
        
        uint64_t N = 1048576;
        uint32_t r = 8;
        uint32_t p = 1;
        
        uint64_t maxmem = 8ULL * 1024 * 1024 * 1024;
        if (EVP_PBE_scrypt(password.c_str(), password.length(),salt.data(), salt.size(),N, r, p, maxmem,key.data(), key_length) != 1) {
            throw std::runtime_error("Scrypt密钥派生失败");
        }
        
        return key;
    } else {
        if (kdf_function.find("SHA-256") != std::string::npos || kdf_function.find("SHA256") != std::string::npos) {
            md = EVP_sha256();
        } else if (kdf_function.find("SHA3-256") != std::string::npos) {
            md = EVP_sha3_256();
        } else if (kdf_function.find("BLAKE2S-256") != std::string::npos) {
            md = EVP_blake2s256();
        } else {
            throw std::runtime_error("不支持的密钥派生方式: " + kdf_function);
        }

        std::vector<unsigned char> key(key_length);
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                              salt.data(), static_cast<int>(salt.size()),
                              iterations,
                              md,
                              static_cast<int>(key_length), key.data()) != 1) {
            throw std::runtime_error("PBKDF2密钥派生失败");
        }

        return key;
    }
}

std::vector<unsigned char> BackgroundProcessing::compute_hmac(const std::vector<unsigned char> &data, 
                                           const std::vector<unsigned char> &key,
                                           const std::string &hash_function) {
    const EVP_MD *md = nullptr;
    
    if (hash_function == "SHA256") {
        md = EVP_sha256();
    } else if (hash_function == "SHA3-256") {
        md = EVP_sha3_256();
    } else if (hash_function == "BLAKE2S-256") {
        md = EVP_blake2s256();
    } else {
        throw std::runtime_error("不支持的HMAC哈希函数: " + hash_function);
    }
    
    std::vector<unsigned char> hmac(EVP_MD_size(md));
    unsigned int hmac_len = 0;
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        throw std::runtime_error("无法创建HMAC上下文");
    }
    
    if (HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), md, nullptr) != 1 ||
        HMAC_Update(ctx, data.data(), data.size()) != 1 ||
        HMAC_Final(ctx, hmac.data(), &hmac_len) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC计算失败");
    }
    
    HMAC_CTX_free(ctx);
    hmac.resize(hmac_len);
    return hmac;
}

bool BackgroundProcessing::verify_hmac(const std::vector<unsigned char> &data, 
                    const std::vector<unsigned char> &hmac,
                    const std::vector<unsigned char> &key,
                    const std::string &hash_function) {
    std::vector<unsigned char> computed_hmac = compute_hmac(data, key, hash_function);
    return computed_hmac == hmac;
}

inline std::string BackgroundProcessing::base64_encode(const std::vector<unsigned char> &data) {
    BioPtr b64(BIO_new(BIO_f_base64()));
    BioPtr bio(BIO_new(BIO_s_mem()));

    if (!b64 || !bio) {
        throw std::runtime_error("无法创建BIO对象");
    }

    bio = BioPtr(BIO_push(b64.release(), bio.release()));
    BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio.get(), data.data(), static_cast<int>(data.size()));
    BIO_flush(bio.get());

    BUF_MEM *bufferPtr = nullptr;
    BIO_get_mem_ptr(bio.get(), &bufferPtr);

    if (!bufferPtr) {
        throw std::runtime_error("无法获取Base64编码结果");
    }

    return std::string(bufferPtr->data, bufferPtr->length);
}

inline std::vector<unsigned char> BackgroundProcessing::base64_decode(const std::string &data) {
    BioPtr b64(BIO_new(BIO_f_base64()));
    BioPtr bio(BIO_new_mem_buf(data.c_str(), static_cast<int>(data.size())));

    if (!b64 || !bio) {
        throw std::runtime_error("无法创建BIO对象");
    }

    bio = BioPtr(BIO_push(b64.release(), bio.release()));
    BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> result(data.size());
    int len = BIO_read(bio.get(), result.data(), static_cast<int>(data.size()));

    if (len > 0) {
        result.resize(static_cast<size_t>(len));
        return result;
    } else {
        throw std::runtime_error("Base64解码失败");
    }
}

// ========== 命令执行和文件操作函数 ==========

inline std::string BackgroundProcessing::execute_command(const std::string &command) {
    if (m_cancelled) {
        return "操作已取消";
    }
    send_progress_signal("执行命令中...");
    std::string output;
    std::string error;
    int exit_status = 0;
    try{
        Glib::spawn_command_line_sync(command, &output, &error, &exit_status);
        if (m_cancelled) {
            return "操作已取消";
        }
        return check_command_result(exit_status, output, error);
    } catch (const Glib::Error &e){
        return "命令执行异常: " + std::string(e.what());
    }
}

inline void BackgroundProcessing::cleanup_comment_file(const std::string &output_path) {
    try{
        size_t last_slash = output_path.find_last_of("/\\");
        if (last_slash != std::string::npos){
            std::string dir_path = output_path.substr(0, last_slash);
            std::string comment_file = dir_path + "/压缩包注释tmp.txt";
            if (std::filesystem::exists(comment_file)){
                if (std::filesystem::remove(comment_file)) {
                    send_progress_signal("已清理临时注释文件: " + comment_file);
                } else {
                    send_progress_signal("警告: 无法删除临时注释文件: " + comment_file);
                }
            }
        }
    } catch (const std::exception &e){
        send_progress_signal("清理注释文件时出错: " + std::string(e.what()));
    }
}

// ========== 信号发送函数 ==========

inline void BackgroundProcessing::send_completion_signal(const std::string &result, bool success) {
    if (m_completion_callback){
        Glib::signal_idle().connect_once([this, result, success]() { m_completion_callback(result, success); });
    }
}

inline void BackgroundProcessing::send_progress_signal(const std::string &message) {
    if (m_progress_callback){
        Glib::signal_idle().connect_once([this, message]() { m_progress_callback(message); });
    }
}

inline void BackgroundProcessing::send_encryption_signal(const std::string &result, bool success, bool is_encryption) {
    if (m_encryption_callback){
        Glib::signal_idle().connect_once([this, result, success, is_encryption]() { m_encryption_callback(result, success, is_encryption); });
    }
}

inline void BackgroundProcessing::send_filename_fix_signal(const std::string &result, bool success) {
    if (m_filename_fix_callback){
        Glib::signal_idle().connect_once([this, result, success]() { m_filename_fix_callback(result, success); });
    }
}