#ifndef BACKGROUNDPROCESSING_H
#define BACKGROUNDPROCESSING_H

// ========== C++ 标准库头文件 ==========
#include <string>
#include <functional>
#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <stack>

// ========== C 标准库头文件 ==========
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <dirent.h>

// ========== 第三方库头文件 ==========
#include <iconv.h>

// OpenSSL 头文件
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>

/**
 * @brief 后台处理类，负责实际的压缩、解压等操作
 *
 * 这个类处理所有与rar和7z工具的交互，包括压缩、解压、列出文件、
 * 测试完整性、获取注释等功能。
 */
class BackgroundProcessing {
public:
    // ========== 回调函数类型定义 ==========
    
    /**
     * @brief 完成回调函数类型定义
     * @param result 操作结果信息
     * @param success 操作是否成功
     */
    using CompletionCallback = std::function<void(const std::string &result, bool success)>;

    /**
     * @brief 进度更新回调函数类型定义
     * @param message 进度信息
     */
    using ProgressCallback = std::function<void(const std::string &message)>;

    /**
     * @brief 加密解密回调函数类型定义
     * @param result 操作结果信息
     * @param success 操作是否成功
     * @param is_encryption 是否为加密操作（true为加密，false为解密）
     */
    using EncryptionCallback = std::function<void(const std::string &result, bool success, bool is_encryption)>;

    /**
     * @brief 文件名修复回调函数类型定义
     * @param result 操作结果信息
     * @param success 操作是否成功
     */
    using FilenameFixCallback = std::function<void(const std::string &result, bool success)>;

    // ========== 构造函数和析构函数 ==========
    
    /**
     * @brief 构造函数
     * @param completion_callback 完成回调函数
     * @param progress_callback 进度回调函数
     * @param encryption_callback 加密解密回调函数
     * @param filename_fix_callback 文件名修复回调函数
     */
    BackgroundProcessing(CompletionCallback completion_callback,
                         ProgressCallback progress_callback,
                         EncryptionCallback encryption_callback = nullptr,
                         FilenameFixCallback filename_fix_callback = nullptr);

    /**
     * @brief 析构函数
     */
    ~BackgroundProcessing();

    // ========== 压缩解压操作函数 ==========

    /**
     * @brief 使用rar进行压缩
     * @param command 压缩命令
     * @param output_path 输出路径（用于注释文件清理）
     */
    void compress_with_rar(const std::string &command, const std::string &output_path);

    /**
     * @brief 使用7z进行压缩
     * @param command 压缩命令
     * @param output_path 输出路径
     */
    void compress_with_7z(const std::string &command, const std::string &output_path);

    /**
     * @brief 使用rar进行解压
     * @param command 解压命令
     * @param archive_path 压缩包路径
     */
    void extract_with_rar(const std::string &command, const std::string &archive_path);

    /**
     * @brief 使用7z进行解压
     * @param command 解压命令
     * @param archive_path 压缩包路径
     */
    void extract_with_7z(const std::string &command, const std::string &archive_path);

    /**
     * @brief 使用unzip进行解压
     * @param command 解压命令
     * @param archive_path 压缩包路径
     */
    void extract_with_unzip(const std::string &command, const std::string &archive_path);

    /**
     * @brief 列出压缩包内容
     * @param command 列出命令
     * @param tool 使用的工具（"rar"或"7z"或"unzip"）
     */
    void list_archive_contents(const std::string &command, const std::string &tool);

    /**
     * @brief 测试压缩包完整性
     * @param command 测试命令
     * @param tool 使用的工具（"rar"或"7z"或"unzip"）
     */
    void test_archive_integrity(const std::string &command, const std::string &tool);

    /**
     * @brief 获取压缩包注释
     * @param command 获取注释命令
     * @param tool 使用的工具（"rar"或"7z"或"unzip"）
     */
    void get_archive_comment(const std::string &command, const std::string &tool);

    // ========== 文本加密解密操作函数 ==========

    /**
     * @brief 文本加密功能
     * @param plaintext 明文字符串
     * @param password 密码字符串
     * @param cipher_mode 加密算法模式
     * @param kdf 密钥派生方式
     */
    void encrypt_text(const std::string &plaintext, const std::string &password,
                      const std::string &cipher_mode, const std::string &kdf);

    /**
     * @brief 文本解密功能
     * @param ciphertext 密文字符串
     * @param password 密码字符串
     * @param cipher_mode 加密算法模式
     * @param kdf 密钥派生方式
     */
    void decrypt_text(const std::string &ciphertext, const std::string &password,
                      const std::string &cipher_mode, const std::string &kdf);

    // ========== 文件名修复操作函数 ==========

    /**
     * @brief 修复文件名编码
     * @param path 文件或目录路径
     */
    void fix_filenames_encoding(const std::string &path);

    /**
     * @brief 取消当前操作
     */
    void cancel_operation();

private:
    // ========== 回调函数成员变量 ==========
    CompletionCallback m_completion_callback;
    ProgressCallback m_progress_callback;
    EncryptionCallback m_encryption_callback;
    FilenameFixCallback m_filename_fix_callback;
    
    // ========== 线程控制成员变量 ==========
    std::atomic<bool> m_cancelled;
    std::unique_ptr<std::thread> m_worker_thread;

    // ========== 压缩解压处理函数 ==========
    void process_rar_compression(const std::string &command, const std::string &output_path);
    void process_7z_compression(const std::string &command);
    void process_unzip_extraction(const std::string &command);
    inline std::string check_command_result(int exit_status, const std::string &output, const std::string &error);

    // ========== 文本加密解密处理函数 ==========
    void process_text_encryption(const std::string &plaintext, const std::string &password,
                                 const std::string &cipher_mode, const std::string &kdf);
    void process_text_decryption(const std::string &ciphertext, const std::string &password,
                                 const std::string &cipher_mode, const std::string &kdf);

    // ========== 文件名修复处理函数 ==========
    void process_filename_fix(const std::string &path);
    std::string fix_filename_encoding(const std::string &filename);
    std::string fix_directory_filenames(const std::string &directory_path);

    // ========== 加密解密实现函数 ==========
    std::string perform_encryption(const std::string &plaintext, const std::string &password,
                                   const std::string &cipher_mode, const std::string &kdf);
    std::string perform_decryption(const std::string &ciphertext, const std::string &password,
                                   const std::string &cipher_mode, const std::string &kdf);

    // ========== 加密工具函数 ==========
    inline std::vector<unsigned char> generate_salt(size_t size);
    std::vector<unsigned char> derive_key(const std::string &password,
                                          const std::vector<unsigned char> &salt,
                                          const std::string &kdf_function,
                                          size_t key_length,
                                          int iterations);
    inline std::string base64_encode(const std::vector<unsigned char> &data);
    inline std::vector<unsigned char> base64_decode(const std::string &data);

    // ========== HMAC相关函数 ==========
    std::vector<unsigned char> compute_hmac(const std::vector<unsigned char> &data, 
                                           const std::vector<unsigned char> &key,
                                           const std::string &hash_function);
    bool verify_hmac(const std::vector<unsigned char> &data, 
                    const std::vector<unsigned char> &hmac,
                    const std::vector<unsigned char> &key,
                    const std::string &hash_function);

    // ========== 命令执行和文件操作函数 ==========
    inline std::string execute_command(const std::string &command);
    inline void cleanup_comment_file(const std::string &output_path);

    // ========== 信号发送函数 ==========
    inline void send_completion_signal(const std::string &result, bool success);
    inline void send_progress_signal(const std::string &message);
    inline void send_encryption_signal(const std::string &result, bool success, bool is_encryption);
    inline void send_filename_fix_signal(const std::string &result, bool success);
};

#endif // BACKGROUNDPROCESSING_H