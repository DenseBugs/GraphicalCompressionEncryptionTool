#include <gtkmm/application.h>
#include <gtkmm/window.h>
#include <gtkmm/button.h>
#include <gtkmm/label.h>
#include <gtkmm/box.h>
#include <gtkmm/filechoosernative.h>
#include <gtkmm/comboboxtext.h>
#include <gtkmm/entry.h>
#include <gtkmm/textview.h>
#include <gtkmm/scrolledwindow.h>
#include <gtkmm/progressbar.h>
#include <gtkmm/spinner.h>
#include <gtkmm/separator.h>
#include <gtkmm/frame.h>
#include <gtkmm/checkbutton.h>
#include <gtkmm/grid.h>
#include <gtkmm/togglebutton.h>
#include <gtkmm/dialog.h>
#include <gtkmm/messagedialog.h>
#include <gtkmm/stack.h>
#include <gtkmm/gestureclick.h>
#include <gtkmm/cssprovider.h>
#include <gtkmm/headerbar.h>
#include <gtkmm/listbox.h>
#include <gtkmm/listboxrow.h>
#include <glibmm/main.h>
#include <glibmm/spawn.h>
#include "backgroundprocessing.h"

class GraphicalCompressionEncryptionToolWindow : public Gtk::Window {
public:
    GraphicalCompressionEncryptionToolWindow();
    ~GraphicalCompressionEncryptionToolWindow();
    static const Glib::ustring help_contents;
    static const Glib::ustring plaintext_contents;
    static const Glib::ustring ciphertext_contents;

private:
    // ========== 枚举定义 ==========
    enum class Mode {
        RAR_COMPRESS,
        SEVENZ_COMPRESS,
        TEST_EXTRACT,
        TEXT_ENCRYPT
    };

    enum class CommandType {
        RAR_COMPRESS,
        SEVENZ_COMPRESS,
        RAR_LIST_FILES,
        SEVENZ_LIST_FILES,
        UNZIP_LIST_FILES,
        RAR_TEST_INTEGRITY,
        SEVENZ_TEST_INTEGRITY,
        UNZIP_TEST_INTEGRITY,
        RAR_GET_COMMENT,
        SEVENZ_GET_COMMENT,
        UNZIP_GET_COMMENT,
        RAR_EXTRACT,
        SEVENZ_EXTRACT,
        UNZIP_EXTRACT
    };

    struct FileListItem {
        std::string name;
        std::string path;
        bool is_directory;
        Gtk::ListBoxRow *row;
        Gtk::Button *remove_button;
        Gtk::Label *index_label;
        Gtk::Label *icon_label;
        Gtk::Label *name_label;
        Gtk::Label *path_label;
    };

    // ========== 主布局组件 ==========
    Gtk::Box m_main_box;
    Gtk::HeaderBar m_header_bar;
    Gtk::Box m_mode_box;
    Gtk::Box m_content_box;
    Gtk::Box m_bottom_box;

    // 标题和模式选择
    Gtk::Label m_title_label;
    Gtk::Label m_mode_label;
    Gtk::ComboBoxText m_mode_combo;

    // 内容区域
    Gtk::Stack m_content_stack;

    // ========== 压缩功能控件 ==========
    Gtk::Box m_compress_box;
    Gtk::Frame m_file_list_frame;
    Gtk::Box m_file_list_box;
    Gtk::ScrolledWindow m_file_list_scrolled;
    Gtk::ListBox m_file_list_box_widget;
    Gtk::Box m_file_buttons_box;
    Gtk::Button m_add_files_button;
    Gtk::Button m_add_folder_button;

    Gtk::Box m_compression_output_box;
    Gtk::Entry m_compression_output_entry;
    Gtk::Button m_compression_output_file_button;
    Gtk::Button m_compression_output_directory_button;

    Gtk::Box m_compression_password_box;
    Gtk::Entry m_compression_password_entry;
    Gtk::ToggleButton m_show_compression_password_button;
    Gtk::ComboBoxText m_compression_encryption_type_combo;

    // 字典大小、单词大小、分卷大小控件
    Gtk::Box m_compression_settings_box;
    Gtk::Box m_dict_box;
    Gtk::Label m_dict_size_label;
    Gtk::ComboBoxText m_dict_size_combo;
    Gtk::Box m_word_box;
    Gtk::Label m_word_size_label;
    Gtk::ComboBoxText m_word_size_combo;
    Gtk::Box m_volume_box;
    Gtk::Label m_volume_label;
    Gtk::Entry m_volume_entry;
    Gtk::Button m_help_button;

    // 压缩设置控件
    Gtk::Box m_compression_options_box;
    Gtk::CheckButton m_solid_checkbutton;
    Gtk::Label m_compression_level_label;
    Gtk::ComboBoxText m_compression_level_combo;

    // 压缩命令和执行控件
    Gtk::Box m_compression_command_box;
    Gtk::Entry m_compression_command_entry;
    Gtk::Button m_show_compression_command_button;
    Gtk::Button m_start_compress_button;

    // 压缩注释控件
    Gtk::Box m_compression_comment_box;
    Gtk::Label m_compression_comment_label;
    Gtk::ScrolledWindow m_compression_comment_scrolled;
    Gtk::TextView m_compression_comment_textview;

    // ========== 解压测试功能控件 ==========
    Gtk::Box m_extract_box;
    Gtk::Box m_archive_box;
    Gtk::Entry m_archive_entry;
    Gtk::Button m_archive_button;

    Gtk::Box m_extract_path_box;
    Gtk::Entry m_extract_path_entry;
    Gtk::Button m_extract_path_button;

    Gtk::Box m_extract_password_box;
    Gtk::Entry m_extract_password_entry;
    Gtk::ToggleButton m_show_extract_password_button;

    Gtk::Box m_extract_tool_box;
    Gtk::Label m_extract_tool_label;
    Gtk::ComboBoxText m_extract_tool_combo;
    Gtk::Box m_extract_buttons_box;
    Gtk::Button m_get_comment_button;
    Gtk::Button m_list_files_button;
    Gtk::Button m_test_integrity_button;
    Gtk::Button m_start_extract_button;

    Gtk::Box m_extract_command_box;
    Gtk::ScrolledWindow m_extract_command_scrolled;
    Gtk::TextView m_extract_command_textview;
    Gtk::Button m_show_extract_command_button;

    // ========== 文件名修复功能控件 ==========
    Gtk::Box m_filename_fix_box;
    Gtk::Label m_filename_fix_label;
    Gtk::Box m_filename_fix_controls_box;
    Gtk::Entry m_filename_fix_entry;
    Gtk::Box m_filename_fix_info_box;
    Gtk::ScrolledWindow m_filename_fix_info_scrolled;
    Gtk::TextView m_filename_fix_info_textview;
    Glib::RefPtr<Gtk::TextBuffer> m_filename_fix_info_buffer;
    Gtk::Box m_filename_fix_buttons_box;
    Gtk::Button m_select_file_button;
    Gtk::Button m_select_directory_button;
    Gtk::Button m_start_fix_button;
    std::string m_actual_fix_path;

    // ========== 文本加密功能控件 ==========
    Gtk::Box m_text_encrypt_box;
    Gtk::ScrolledWindow m_plaintext_scrolled;
    Gtk::TextView m_plaintext_textview;
    Gtk::ScrolledWindow m_ciphertext_scrolled;
    Gtk::TextView m_ciphertext_textview;

    Gtk::Box m_text_encryption_algorithm_box;
    Gtk::Label m_text_cipher_mode_label;
    Gtk::ComboBoxText m_text_cipher_mode_combo;
    Gtk::Label m_text_kdf_label;
    Gtk::ComboBoxText m_text_kdf_combo;

    Gtk::Box m_text_encryption_password_box;
    Gtk::Label m_text_encryption_password_label;
    Gtk::Entry m_text_encryption_password_entry;
    Gtk::ToggleButton m_show_text_encryption_password_button;
    Gtk::Button m_text_encrypt_button;
    Gtk::Button m_text_decrypt_button;

    // ========== 底部日志区域 ==========
    Gtk::Label m_log_label;
    Gtk::ScrolledWindow m_log_scrolled;
    Gtk::TextView m_log_textview;
    Glib::RefPtr<Gtk::TextBuffer> m_log_buffer;

    // ========== 状态变量 ==========
    Mode m_current_mode{Mode::RAR_COMPRESS};
    std::atomic<bool> m_processing{false};
    std::vector<FileListItem> m_file_list;
    Glib::RefPtr<Gtk::TextBuffer> m_plaintext_buffer;
    Glib::RefPtr<Gtk::TextBuffer> m_ciphertext_buffer;
    Glib::RefPtr<Gtk::TextBuffer> m_extract_command_buffer;
    Glib::RefPtr<Gtk::TextBuffer> m_compression_comment_buffer;
    int m_file_counter{0};
    bool m_7zz_available{false};
    bool m_7z_available{false};
    bool m_rar_available{false};
    std::string m_desktop_path;
    std::string m_archive_base_name;

    // 后台处理对象
    std::unique_ptr<BackgroundProcessing> m_background_processor;

    // ========== 压缩功能信号处理函数 ==========
    void on_mode_changed();
    void update_content_visibility();
    void on_add_files_clicked();
    void on_add_folder_clicked();
    void on_remove_file_clicked(const std::string &path);
    void on_compression_output_file_button_clicked();
    void on_compression_output_directory_button_clicked();
    void on_show_compression_password_toggled();
    void on_show_compression_command_clicked();
    void on_start_compress_clicked();
    void on_compression_password_changed();
    void on_compression_output_changed();
    void on_volume_changed();

    // ========== 解压测试功能信号处理函数 ==========
    void on_archive_button_clicked();
    void on_extract_path_button_clicked();
    void on_show_extract_password_toggled();
    void on_show_extract_command_clicked();
    void on_test_integrity_clicked();
    void on_list_files_clicked();
    void on_get_comment_clicked();
    void on_start_extract_clicked();
    void on_extract_path_changed();

    // ========== 文件名修复功能信号处理函数 ==========
    void on_select_file_clicked();
    void on_select_directory_clicked();
    void on_start_fix_clicked();
    void update_filename_fix_info();
    std::string get_safe_display_path(const std::string& path, bool is_directory);

    // ========== 文本加密功能信号处理函数 ==========
    void on_show_text_encryption_password_toggled();
    void on_text_encrypt_clicked();
    void on_text_decrypt_clicked();

    // ========== 输入验证函数 ==========
    bool validate_volume_format(const std::string &volume);
    std::string convert_volume_to_lower(const std::string &volume);
    std::string get_dict_size_value();
    std::string get_word_size_value();
    std::string get_compression_level_value();
    void create_comment_file(const std::string &output_path);
    inline bool validate_path_security(const std::string &path);
    bool validate_volume_value(const std::string &volume);
    bool validate_compression_output_extension(const std::string &path);
    bool validate_compression_output_path(const std::string &path);
    bool validate_extract_path(const std::string &path);
    std::string validate_compress_inputs();
    std::string validate_extract_inputs();

    // ========== 界面辅助函数 ==========
    void show_help_dialog();
    void update_compress_command_display();
    void update_extract_command_display();
    void set_control_validation(Gtk::Widget &widget, bool valid);
    void clear_file_list();
    void add_file_to_list(const std::string &path, bool is_directory);
    void update_extract_tool_default();
    void update_extract_tool_by_archive(const std::string& archive_path);

    // ========== 工具检测函数 ==========
    void check_tools_async();
    void check_rar_version();
    void check_7z_version();
    void append_to_log(const std::string &text, bool is_error = false);
    std::string get_current_time();

    // ========== 命令行构建函数 ==========
    std::string build_command(CommandType type, bool for_display = false);
    
    // 内联的具体命令构建函数
    inline std::string build_rar_compress_command_inline(bool for_display);
    inline std::string build_7z_compress_command_inline(bool for_display);
    inline std::string build_rar_list_files_command_inline(bool for_display);
    inline std::string build_7z_list_files_command_inline(bool for_display);
    inline std::string build_unzip_list_files_command_inline(bool for_display);
    inline std::string build_rar_test_integrity_command_inline(bool for_display);
    inline std::string build_7z_test_integrity_command_inline(bool for_display);
    inline std::string build_unzip_test_integrity_command_inline(bool for_display);
    inline std::string build_rar_get_comment_command_inline(bool for_display);
    inline std::string build_7z_get_comment_command_inline(bool for_display);
    inline std::string build_unzip_get_comment_command_inline(bool for_display);
    inline std::string build_rar_extract_command_inline(bool for_display);
    inline std::string build_7z_extract_command_inline(bool for_display);
    inline std::string build_unzip_extract_command_inline(bool for_display);

    // ========== 后台处理回调 ==========
    void on_rar7z_operation_completed(const std::string &result, bool success);
    void on_progress_update(const std::string &message);
    void on_text_encryption_completed(const std::string &result, bool success, bool is_encryption);
    void on_filename_fix_completed(const std::string &result, bool success);

    // ========== 窗口关闭处理 ==========
    bool on_close_request() override;
};

// ========== 类成员函数实现 ==========

GraphicalCompressionEncryptionToolWindow::GraphicalCompressionEncryptionToolWindow()
    : m_main_box(Gtk::Orientation::VERTICAL, 0),
      m_mode_box(Gtk::Orientation::HORIZONTAL, 10),
      m_content_box(Gtk::Orientation::VERTICAL, 0),
      m_bottom_box(Gtk::Orientation::VERTICAL, 12),
      m_compress_box(Gtk::Orientation::VERTICAL, 8),
      m_file_list_box(Gtk::Orientation::HORIZONTAL, 8),
      m_file_buttons_box(Gtk::Orientation::VERTICAL, 5),
      m_compression_output_box(Gtk::Orientation::HORIZONTAL, 10),
      m_compression_password_box(Gtk::Orientation::HORIZONTAL, 10),
      m_compression_settings_box(Gtk::Orientation::HORIZONTAL, 20),
      m_dict_box(Gtk::Orientation::HORIZONTAL, 5),
      m_word_box(Gtk::Orientation::HORIZONTAL, 5),
      m_volume_box(Gtk::Orientation::HORIZONTAL, 5),
      m_compression_options_box(Gtk::Orientation::HORIZONTAL, 10),
      m_compression_command_box(Gtk::Orientation::HORIZONTAL, 10),
      m_compression_comment_box(Gtk::Orientation::VERTICAL, 5),
      m_extract_box(Gtk::Orientation::VERTICAL, 8),
      m_archive_box(Gtk::Orientation::HORIZONTAL, 10),
      m_extract_path_box(Gtk::Orientation::HORIZONTAL, 10),
      m_extract_password_box(Gtk::Orientation::HORIZONTAL, 10),
      m_extract_tool_box(Gtk::Orientation::HORIZONTAL, 10),
      m_extract_buttons_box(Gtk::Orientation::HORIZONTAL, 10),
      m_extract_command_box(Gtk::Orientation::HORIZONTAL, 10),
      m_filename_fix_box(Gtk::Orientation::VERTICAL, 8),
      m_filename_fix_controls_box(Gtk::Orientation::HORIZONTAL, 10),
      m_filename_fix_info_box(Gtk::Orientation::HORIZONTAL, 10),
      m_filename_fix_buttons_box(Gtk::Orientation::VERTICAL, 5),
      m_text_encrypt_box(Gtk::Orientation::VERTICAL, 8),
      m_text_encryption_algorithm_box(Gtk::Orientation::HORIZONTAL, 20),
      m_text_encryption_password_box(Gtk::Orientation::HORIZONTAL, 10) {

    set_title("图形化压缩加密辅助工具3.1-gtk4");
    set_default_size(860, 800);
    set_resizable(true);

    // 获取桌面路径
    const char *home_dir = getenv("HOME");
    if (home_dir) {
        std::vector<std::string> desktop_names = {"Desktop", "桌面"};
        for (const auto &name : desktop_names) {
            std::string desktop_path = std::string(home_dir) + "/" + name;
            if (access(desktop_path.c_str(), F_OK) == 0 && access(desktop_path.c_str(), W_OK) == 0) {
                m_desktop_path = desktop_path;
                break;
            }
        }
        if (m_desktop_path.empty() && access(home_dir, W_OK) == 0) {
            m_desktop_path = home_dir;
        }
    }
    m_archive_base_name = "待重命名压缩包";

    // 初始化后台处理器
    m_background_processor = std::make_unique<BackgroundProcessing>(
        [this](const std::string &result, bool success) {
            on_rar7z_operation_completed(result, success);
        },
        [this](const std::string &message) {
            on_progress_update(message);
        },
        [this](const std::string &result, bool success, bool is_encryption) {
            on_text_encryption_completed(result, success, is_encryption);
        },
        [this](const std::string &result, bool success) {
            on_filename_fix_completed(result, success);
        });

    // === 使用HeaderBar实现标题栏 ===
    m_header_bar.set_title_widget(m_title_label);
    m_header_bar.set_show_title_buttons(true);

    m_title_label.set_markup("<span size='large' weight='bold'>图形化压缩加密辅助工具3.1-gtk4</span>");
    m_title_label.set_halign(Gtk::Align::CENTER);

    m_mode_label.set_text("工作模式:");
    m_mode_combo.append("RAR压缩");
    m_mode_combo.append("7z压缩");
    m_mode_combo.append("测试解压");
    m_mode_combo.append("文本加密");
    m_mode_combo.set_active(0);
    m_mode_combo.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_mode_changed));

    m_mode_box.append(m_mode_label);
    m_mode_box.append(m_mode_combo);
    m_header_bar.pack_end(m_mode_box);

    set_titlebar(m_header_bar);
    m_main_box.set_margin(12);

    // === 内容堆栈 ===
    m_content_stack.set_transition_type(Gtk::StackTransitionType::CROSSFADE);

    // === 文件压缩模式 ===
    m_file_list_frame.set_label("文件列表");
    m_file_list_frame.set_label_align(Gtk::Align::CENTER);

    m_file_list_box_widget.set_selection_mode(Gtk::SelectionMode::NONE);
    m_file_list_box_widget.set_hexpand(true);

    m_file_list_scrolled.set_child(m_file_list_box_widget);
    m_file_list_scrolled.set_min_content_height(180);
    m_file_list_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    m_file_list_scrolled.set_hexpand(true);

    m_add_files_button.set_label("添加文件");
    m_add_files_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_add_files_clicked));

    m_add_folder_button.set_label("添加文件夹");
    m_add_folder_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_add_folder_clicked));

    m_file_buttons_box.append(m_add_files_button);
    m_file_buttons_box.append(m_add_folder_button);
    // 设置按钮框在竖直方向上居中
    m_file_buttons_box.set_valign(Gtk::Align::CENTER);

    m_file_list_box.append(m_file_list_scrolled);
    m_file_list_box.append(m_file_buttons_box);
    m_file_list_frame.set_child(m_file_list_box);
    m_compress_box.append(m_file_list_frame);

    // 输出路径
    auto compression_output_label = Gtk::make_managed<Gtk::Label>("输出文件:");
    m_compression_output_entry.set_hexpand(true);
    m_compression_output_entry.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_compression_output_changed));
    m_compression_output_file_button.set_label("输出文件...");
    m_compression_output_file_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_compression_output_file_button_clicked));
    m_compression_output_directory_button.set_label("选择目录");
    m_compression_output_directory_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_compression_output_directory_button_clicked));

    m_compression_output_box.append(*compression_output_label);
    m_compression_output_box.append(m_compression_output_entry);
    m_compression_output_box.append(m_compression_output_file_button);
    m_compression_output_box.append(m_compression_output_directory_button);
    m_compress_box.append(m_compression_output_box);

    // 密码设置
    auto compression_password_label = Gtk::make_managed<Gtk::Label>("密码:");
    m_compression_password_entry.set_visibility(false);
    m_compression_password_entry.set_hexpand(true);
    m_compression_password_entry.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_compression_password_changed));
    m_show_compression_password_button.set_label("显示密码");
    m_show_compression_password_button.signal_toggled().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_show_compression_password_toggled));

    m_compression_encryption_type_combo.append("无密码");
    m_compression_encryption_type_combo.append("仅加密压缩包内的文件内容");
    m_compression_encryption_type_combo.append("加密压缩包内文件名和文件内容");
    m_compression_encryption_type_combo.set_active(0);
    m_compression_encryption_type_combo.signal_changed().connect([this]() { update_compress_command_display(); });

    m_compression_password_box.append(*compression_password_label);
    m_compression_password_box.append(m_compression_password_entry);
    m_compression_password_box.append(m_show_compression_password_button);
    m_compression_password_box.append(m_compression_encryption_type_combo);
    m_compress_box.append(m_compression_password_box);

    // 字典大小和单词大小
    m_dict_size_label.set_text("字典大小:");
    m_dict_size_combo.append("4MB");
    m_dict_size_combo.append("8MB");
    m_dict_size_combo.append("16MB");
    m_dict_size_combo.append("32MB");
    m_dict_size_combo.append("64MB");
    m_dict_size_combo.append("128MB");
    m_dict_size_combo.append("256MB");
    m_dict_size_combo.append("512MB");
    m_dict_size_combo.append("1GB");
    m_dict_size_combo.append("2GB");
    m_dict_size_combo.append("4GB");
    m_dict_size_combo.append("8GB");
    m_dict_size_combo.append("16GB");
    m_dict_size_combo.append("32GB");
    m_dict_size_combo.append("64GB");
    m_dict_size_combo.set_active(8);
    m_dict_size_combo.signal_changed().connect([this]() { update_compress_command_display(); });

    m_word_size_label.set_text("单词大小:");
    m_word_size_combo.append("32");
    m_word_size_combo.append("64");
    m_word_size_combo.append("128");
    m_word_size_combo.append("192");
    m_word_size_combo.append("256");
    m_word_size_combo.append("273");
    m_word_size_combo.set_active(2);
    m_word_size_combo.set_sensitive(false);
    m_word_size_combo.signal_changed().connect([this]() { update_compress_command_display(); });

    // 分卷大小
    m_volume_label.set_text("分卷大小:");
    m_volume_entry.set_placeholder_text("留空不分卷，输入如: 256K/32M/1G");
    m_volume_entry.set_hexpand(true);
    m_volume_entry.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_volume_changed));

    m_help_button.set_label("帮助信息");
    m_help_button.set_halign(Gtk::Align::END);
    m_help_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::show_help_dialog));

    m_dict_box.append(m_dict_size_label);
    m_dict_box.append(m_dict_size_combo);

    m_word_box.append(m_word_size_label);
    m_word_box.append(m_word_size_combo);

    m_volume_box.append(m_volume_label);
    m_volume_box.append(m_volume_entry);

    m_compression_settings_box.append(m_dict_box);
    m_compression_settings_box.append(m_word_box);
    m_compression_settings_box.append(m_volume_box);
    m_compression_settings_box.append(m_help_button);
    m_compression_settings_box.set_halign(Gtk::Align::FILL);
    m_compress_box.append(m_compression_settings_box);

    // 固实压缩、压缩级别
    m_solid_checkbutton.set_label("固实压缩");
    m_solid_checkbutton.set_active(true);
    m_solid_checkbutton.signal_toggled().connect([this]() { update_compress_command_display(); });

    m_compression_level_label.set_text("压缩级别:");
    m_compression_level_combo.append("默认");
    m_compression_level_combo.append("较好");
    m_compression_level_combo.append("最好");
    m_compression_level_combo.set_active(2);
    m_compression_level_combo.signal_changed().connect([this]() { update_compress_command_display(); });

    // 命令显示和执行
    m_compression_command_entry.set_hexpand(true);
    m_show_compression_command_button.set_label("显示压缩命令");
    m_show_compression_command_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_show_compression_command_clicked));
    m_start_compress_button.set_label("开始压缩");
    m_start_compress_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_start_compress_clicked));

    m_compression_options_box.append(m_solid_checkbutton);
    m_compression_options_box.append(m_compression_level_label);
    m_compression_options_box.append(m_compression_level_combo);

    m_compression_command_box.append(m_compression_options_box);
    m_compression_command_box.append(m_compression_command_entry);
    m_compression_command_box.append(m_show_compression_command_button);
    m_compression_command_box.append(m_start_compress_button);
    m_compress_box.append(m_compression_command_box);

    // 注释区域
    m_compression_comment_label.set_text("注释内容");
    m_compression_comment_label.set_halign(Gtk::Align::CENTER);

    m_compression_comment_buffer = Gtk::TextBuffer::create();
    m_compression_comment_textview.set_buffer(m_compression_comment_buffer);
    m_compression_comment_textview.set_wrap_mode(Gtk::WrapMode::WORD);
    m_compression_comment_scrolled.set_child(m_compression_comment_textview);
    m_compression_comment_scrolled.set_min_content_height(90);
    m_compression_comment_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);

    m_compression_comment_box.append(m_compression_comment_label);
    m_compression_comment_box.append(m_compression_comment_scrolled);
    m_compress_box.append(m_compression_comment_box);

    m_content_stack.add(m_compress_box, "compress", "文件压缩");

    // 连接注释内容改变信号
    m_compression_comment_buffer->signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::update_compress_command_display));

    // === 测试解压模式 ===
    auto archive_label = Gtk::make_managed<Gtk::Label>("压缩包:");
    m_archive_entry.set_editable(false);
    m_archive_entry.set_hexpand(true);
    m_archive_entry.signal_changed().connect([this]() {
        update_extract_tool_by_archive(m_archive_entry.get_text());
        update_extract_command_display();
    });
    m_archive_button.set_label("选择压缩包");
    m_archive_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_archive_button_clicked));

    m_archive_box.append(*archive_label);
    m_archive_box.append(m_archive_entry);
    m_archive_box.append(m_archive_button);
    m_extract_box.append(m_archive_box);

    auto extract_path_label = Gtk::make_managed<Gtk::Label>("解压目录:");
    m_extract_path_entry.set_hexpand(true);
    m_extract_path_entry.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_extract_path_changed));
    m_extract_path_button.set_label("选择解压目录");
    m_extract_path_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_extract_path_button_clicked));

    m_extract_path_box.append(*extract_path_label);
    m_extract_path_box.append(m_extract_path_entry);
    m_extract_path_box.append(m_extract_path_button);
    m_extract_box.append(m_extract_path_box);

    auto extract_password_label = Gtk::make_managed<Gtk::Label>("密码:");
    m_extract_password_entry.set_visibility(false);
    m_extract_password_entry.set_hexpand(true);
    m_extract_password_entry.signal_changed().connect([this]() { update_extract_command_display(); });
    m_show_extract_password_button.set_label("显示密码");
    m_show_extract_password_button.signal_toggled().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_show_extract_password_toggled));

    m_extract_password_box.append(*extract_password_label);
    m_extract_password_box.append(m_extract_password_entry);
    m_extract_password_box.append(m_show_extract_password_button);
    m_extract_box.append(m_extract_password_box);

    m_extract_tool_label.set_text("调用工具:");
    m_extract_tool_combo.append("rar");
    m_extract_tool_combo.append("7z");
    m_extract_tool_combo.append("unzip");
    m_extract_tool_combo.signal_changed().connect([this]() { update_extract_command_display(); });

    m_extract_buttons_box.set_halign(Gtk::Align::END);
    m_extract_buttons_box.set_hexpand(true);
    m_extract_buttons_box.set_homogeneous(true);

    m_get_comment_button.set_label("获取注释");
    m_get_comment_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_get_comment_clicked));

    m_list_files_button.set_label("列出文件");
    m_list_files_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_list_files_clicked));

    m_test_integrity_button.set_label("测试完整性");
    m_test_integrity_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_test_integrity_clicked));

    m_start_extract_button.set_label("开始解压");
    m_start_extract_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_start_extract_clicked));

    m_extract_buttons_box.append(m_get_comment_button);
    m_extract_buttons_box.append(m_list_files_button);
    m_extract_buttons_box.append(m_test_integrity_button);
    m_extract_buttons_box.append(m_start_extract_button);

    m_extract_tool_box.append(m_extract_tool_label);
    m_extract_tool_box.append(m_extract_tool_combo);
    m_extract_tool_box.append(m_extract_buttons_box);
    m_extract_tool_box.set_halign(Gtk::Align::FILL);
    m_extract_box.append(m_extract_tool_box);

    m_extract_command_buffer = Gtk::TextBuffer::create();
    m_extract_command_textview.set_buffer(m_extract_command_buffer);
    m_extract_command_textview.set_wrap_mode(Gtk::WrapMode::WORD);
    m_extract_command_textview.set_editable(true);

    m_extract_command_scrolled.set_child(m_extract_command_textview);
    m_extract_command_scrolled.set_min_content_height(80);
    m_extract_command_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    m_extract_command_scrolled.set_hexpand(true);

    m_show_extract_command_button.set_label("显示完整测试解压命令");
    m_show_extract_command_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_show_extract_command_clicked));

    m_extract_command_box.append(m_extract_command_scrolled);
    m_extract_command_box.append(m_show_extract_command_button);
    m_extract_box.append(m_extract_command_box);

    // === 文件名乱码修复功能 ===
    m_filename_fix_label.set_text("文件名乱码修复(7z解压的文件名修复效果差,建议调用rar或其他方式重新解压重试)");
    m_filename_fix_label.set_halign(Gtk::Align::CENTER);

    m_filename_fix_entry.set_hexpand(true);
    m_filename_fix_entry.set_editable(false);
    m_filename_fix_entry.signal_changed().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::update_filename_fix_info));

    m_filename_fix_info_buffer = Gtk::TextBuffer::create();
    m_filename_fix_info_textview.set_buffer(m_filename_fix_info_buffer);
    m_filename_fix_info_textview.set_wrap_mode(Gtk::WrapMode::WORD);
    m_filename_fix_info_textview.set_editable(true);
    m_filename_fix_info_textview.set_hexpand(true);

    m_filename_fix_info_scrolled.set_child(m_filename_fix_info_textview);
    m_filename_fix_info_scrolled.set_min_content_height(100);
    m_filename_fix_info_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    m_filename_fix_info_scrolled.set_hexpand(true);

    m_select_file_button.set_label("选择待转码文件名的单个文件");
    m_select_file_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_select_file_clicked));

    m_select_directory_button.set_label("选择待转码文件名的批量文件目录");
    m_select_directory_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_select_directory_clicked));

    m_start_fix_button.set_label("开始将其他中文编码转码UTF-8");
    m_start_fix_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_start_fix_clicked));

    m_filename_fix_buttons_box.append(m_select_file_button);
    m_filename_fix_buttons_box.append(m_select_directory_button);

    m_filename_fix_controls_box.append(m_filename_fix_entry);
    m_filename_fix_controls_box.append(m_filename_fix_buttons_box);

    m_filename_fix_info_box.append(m_filename_fix_info_scrolled);
    m_filename_fix_info_box.append(m_start_fix_button);

    m_filename_fix_box.append(m_filename_fix_label);
    m_filename_fix_box.append(m_filename_fix_controls_box);
    m_filename_fix_box.append(m_filename_fix_info_box);

    m_extract_box.append(m_filename_fix_box);

    m_extract_box.set_spacing(8);
    m_extract_box.set_vexpand(false);
    m_extract_box.set_valign(Gtk::Align::START);

    m_content_stack.add(m_extract_box, "extract", "测试解压");

    // === 文本加密模式 ===
    m_plaintext_buffer = Gtk::TextBuffer::create();
    m_plaintext_textview.set_buffer(m_plaintext_buffer);
    m_plaintext_textview.set_wrap_mode(Gtk::WrapMode::WORD);
    m_plaintext_buffer->set_text(plaintext_contents);
    m_plaintext_scrolled.set_child(m_plaintext_textview);
    m_plaintext_scrolled.set_min_content_height(190);
    m_plaintext_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);

    m_ciphertext_buffer = Gtk::TextBuffer::create();
    m_ciphertext_textview.set_buffer(m_ciphertext_buffer);
    m_ciphertext_textview.set_wrap_mode(Gtk::WrapMode::WORD);
    m_ciphertext_textview.set_editable(true);
    m_ciphertext_buffer->set_text(ciphertext_contents);
    m_ciphertext_scrolled.set_child(m_ciphertext_textview);
    m_ciphertext_scrolled.set_min_content_height(190);
    m_ciphertext_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);

    m_text_encrypt_box.append(m_plaintext_scrolled);
    m_text_encrypt_box.append(m_ciphertext_scrolled);

    m_text_cipher_mode_label.set_text("加密算法模式:");
    m_text_cipher_mode_combo.append("AES-256-GCM");
    m_text_cipher_mode_combo.append("AES-256-CBC + HMAC");
    m_text_cipher_mode_combo.set_active(0);

    m_text_kdf_label.set_text("密钥派生方式:");
    m_text_kdf_combo.append("Scrypt N=2^20 r=8 p=1");
    m_text_kdf_combo.append("PBKDF2 + SHA-256 | 320,000");
    m_text_kdf_combo.append("PBKDF2 + SHA3-256 | 320,000");
    m_text_kdf_combo.append("PBKDF2 + BLAKE2S-256 | 320,000");
    m_text_kdf_combo.set_active(2);

    m_text_encryption_algorithm_box.append(m_text_cipher_mode_label);
    m_text_encryption_algorithm_box.append(m_text_cipher_mode_combo);
    m_text_encryption_algorithm_box.append(m_text_kdf_label);
    m_text_encryption_algorithm_box.append(m_text_kdf_combo);
    m_text_encryption_algorithm_box.set_halign(Gtk::Align::CENTER);
    m_text_encrypt_box.append(m_text_encryption_algorithm_box);

    m_text_encryption_password_label.set_text("密码:");
    m_text_encryption_password_entry.set_visibility(false);
    m_text_encryption_password_entry.set_hexpand(true);
    m_show_text_encryption_password_button.set_label("显示密码");
    m_show_text_encryption_password_button.signal_toggled().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_show_text_encryption_password_toggled));

    m_text_encrypt_button.set_label("加密");
    m_text_encrypt_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_text_encrypt_clicked));
    m_text_decrypt_button.set_label("解密");
    m_text_decrypt_button.signal_clicked().connect(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_text_decrypt_clicked));

    m_text_encryption_password_box.append(m_text_encryption_password_label);
    m_text_encryption_password_box.append(m_text_encryption_password_entry);
    m_text_encryption_password_box.append(m_show_text_encryption_password_button);
    m_text_encryption_password_box.append(m_text_encrypt_button);
    m_text_encryption_password_box.append(m_text_decrypt_button);
    m_text_encrypt_box.append(m_text_encryption_password_box);

    m_text_encrypt_box.set_spacing(8);
    m_text_encrypt_box.set_vexpand(false);
    m_text_encrypt_box.set_valign(Gtk::Align::START);

    m_content_stack.add(m_text_encrypt_box, "encrypt", "文本加密");

    // 设置布局属性
    m_compress_box.set_spacing(8);
    m_compress_box.set_vexpand(false);
    m_compress_box.set_valign(Gtk::Align::START);
    m_content_stack.set_vexpand(false);
    m_content_stack.set_valign(Gtk::Align::START);

    m_content_box.append(m_content_stack);

    // === 底部日志区域 ===
    m_log_label.set_text("操作日志");
    m_log_label.set_halign(Gtk::Align::CENTER);

    m_log_buffer = Gtk::TextBuffer::create();
    m_log_textview.set_buffer(m_log_buffer);
    m_log_textview.set_editable(true);
    m_log_textview.set_wrap_mode(Gtk::WrapMode::WORD);

    m_log_scrolled.set_child(m_log_textview);
    m_log_scrolled.set_min_content_height(120);
    m_log_scrolled.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    m_log_scrolled.set_vexpand(true);

    m_bottom_box.append(m_log_label);
    m_bottom_box.append(m_log_scrolled);
    m_bottom_box.set_vexpand(true);

    // === 主布局组装 ===
    m_content_box.set_vexpand(false);
    m_content_box.set_valign(Gtk::Align::START);

    m_main_box.append(m_content_box);
    m_main_box.append(m_bottom_box);
    m_main_box.set_vexpand(true);

    set_child(m_main_box);

    // 设置按钮样式
    auto style_context_compress = m_start_compress_button.get_style_context();
    auto style_context_extract = m_start_extract_button.get_style_context();
    auto style_context_encrypt = m_text_encrypt_button.get_style_context();
    auto style_context_decrypt = m_text_decrypt_button.get_style_context();
    auto style_context_fix = m_start_fix_button.get_style_context();

    style_context_compress->add_class("blue-button");
    style_context_extract->add_class("blue-button");
    style_context_encrypt->add_class("blue-button");
    style_context_decrypt->add_class("blue-button");
    style_context_fix->add_class("blue-button");

    // 设置默认路径
    if (!m_desktop_path.empty()) {
        std::string default_output = m_desktop_path + "/" + m_archive_base_name + ".rar";
        m_compression_output_entry.set_text(default_output);
        m_extract_path_entry.set_text(m_desktop_path);
    }

    update_content_visibility();
    append_to_log("图形化压缩加密辅助工具3.1-gtk4 已启动，开始检测rar和7z...\n");

    // 异步检测工具
    check_tools_async();

    //检测输出目录
    on_compression_output_changed();
    on_extract_path_changed();
}

GraphicalCompressionEncryptionToolWindow::~GraphicalCompressionEncryptionToolWindow() {
    clear_file_list();
}

// ========== 窗口关闭处理函数 ==========

bool GraphicalCompressionEncryptionToolWindow::on_close_request() {
    if (m_processing) {
        auto dialog = new Gtk::MessageDialog(*this, 
            "操作中强制退出很可能直接卡死!\n敬请等待操作结束!",false,Gtk::MessageType::INFO,Gtk::ButtonsType::OK,true);      
        dialog->set_title("暂无中止策略!");
        dialog->set_modal(true);
        dialog->signal_response().connect([this, dialog](int response_id) {
            delete dialog;
            append_to_log("用户尝试退出操作...\n");
        });
        dialog->show();
        return true;
    }
    return false;
}

// ========== 文件列表管理函数 ==========

void GraphicalCompressionEncryptionToolWindow::clear_file_list() {
    for (auto &item : m_file_list) {
        if (item.row) {
            m_file_list_box_widget.remove(*item.row);
        }
    }
    m_file_list.clear();
    m_file_counter = 0;
}

void GraphicalCompressionEncryptionToolWindow::add_file_to_list(const std::string &path, bool is_directory) {
    if (!validate_path_security(path)) {
        append_to_log("错误: 文件路径包含不安全字符，已拒绝添加: " + path + "\n", true);
        return;
    }

    for (const auto &item : m_file_list) {
        if (item.path == path) {
            return;
        }
    }

    FileListItem new_item;
    std::filesystem::path p(path);
    new_item.name = p.filename().string();
    new_item.path = path;
    new_item.is_directory = is_directory;

    new_item.row = Gtk::make_managed<Gtk::ListBoxRow>();
    auto row_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 5);
    row_box->set_margin(5);

    new_item.remove_button = Gtk::make_managed<Gtk::Button>("移除");
    new_item.remove_button->set_size_request(60, -1);
    new_item.remove_button->signal_clicked().connect(
        sigc::bind(sigc::mem_fun(*this, &GraphicalCompressionEncryptionToolWindow::on_remove_file_clicked), path));

    m_file_counter++;
    new_item.index_label = Gtk::make_managed<Gtk::Label>(std::to_string(m_file_counter));
    new_item.index_label->set_width_chars(3);
    new_item.index_label->set_xalign(0.5f);

    new_item.icon_label = Gtk::make_managed<Gtk::Label>(is_directory ? "📂" : "📄");
    new_item.icon_label->set_width_chars(2);

    new_item.name_label = Gtk::make_managed<Gtk::Label>(new_item.name);
    new_item.name_label->set_halign(Gtk::Align::START);
    new_item.name_label->set_hexpand(true);

    new_item.path_label = Gtk::make_managed<Gtk::Label>(path);
    new_item.path_label->set_halign(Gtk::Align::START);
    new_item.path_label->set_hexpand(true);
    new_item.path_label->set_ellipsize(Pango::EllipsizeMode::MIDDLE);

    row_box->append(*new_item.remove_button);
    row_box->append(*new_item.index_label);
    row_box->append(*new_item.icon_label);
    row_box->append(*new_item.name_label);
    row_box->append(*new_item.path_label);

    new_item.row->set_child(*row_box);
    m_file_list_box_widget.append(*new_item.row);

    m_file_list.push_back(new_item);
    append_to_log((is_directory ? "添加文件夹: " : "添加文件: ") + path + "\n");
    
    // 如果是文件夹，更新压缩包基础名称
    if (is_directory) {
        m_archive_base_name = p.filename().string();
        std::string output_dir = std::filesystem::path(m_compression_output_entry.get_text()).parent_path().string();
        std::string new_output = output_dir + "/" + m_archive_base_name + 
                                (m_current_mode == Mode::RAR_COMPRESS ? ".rar" : ".7z");
        m_compression_output_entry.set_text(new_output);
    }
    
    update_compress_command_display();
}

// ========== 模式切换和界面更新函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_mode_changed() {
    switch (m_mode_combo.get_active_row_number()) {
        case 0: m_current_mode = Mode::RAR_COMPRESS; break;
        case 1: m_current_mode = Mode::SEVENZ_COMPRESS; break;
        case 2: m_current_mode = Mode::TEST_EXTRACT; break;
        case 3: m_current_mode = Mode::TEXT_ENCRYPT; break;
        default: m_current_mode = Mode::RAR_COMPRESS; break;
    }
    update_content_visibility();

    Glib::signal_idle().connect_once([this]() {
        if (m_current_mode == Mode::RAR_COMPRESS) {
            m_word_size_combo.set_sensitive(false);
            m_dict_size_combo.set_active(8);
            if (!m_desktop_path.empty()) {
                std::string output_dir = std::filesystem::path(m_compression_output_entry.get_text()).parent_path().string();
                m_compression_output_entry.set_text(output_dir + "/" + m_archive_base_name + ".rar");
            } else {
                m_compression_output_entry.set_text(m_archive_base_name + ".rar");
            }
            m_compression_comment_box.set_visible(true);
        } else if (m_current_mode == Mode::SEVENZ_COMPRESS) {
            m_word_size_combo.set_sensitive(true);
            m_dict_size_combo.set_active(7);
            if (!m_desktop_path.empty()) {
                std::string output_dir = std::filesystem::path(m_compression_output_entry.get_text()).parent_path().string();
                m_compression_output_entry.set_text(output_dir + "/" + m_archive_base_name + ".7z");
            } else {
                m_compression_output_entry.set_text(m_archive_base_name + ".7z");
            }
            m_compression_comment_box.set_visible(false);
        } else {
            m_compression_comment_box.set_visible(false);
        }

        update_compress_command_display(); });
}

void GraphicalCompressionEncryptionToolWindow::update_content_visibility() {
    switch (m_current_mode) {
        case Mode::RAR_COMPRESS:
        case Mode::SEVENZ_COMPRESS:
            m_content_stack.set_visible_child(m_compress_box);
            break;
        case Mode::TEST_EXTRACT:
            m_content_stack.set_visible_child(m_extract_box);
            break;
        case Mode::TEXT_ENCRYPT:
            m_content_stack.set_visible_child(m_text_encrypt_box);
            break;
    }
}

// ========== 文件操作函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_add_files_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择要压缩的文件", *this, Gtk::FileChooser::Action::OPEN, "选择", "取消");
    dialog->set_select_multiple(true);

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto files = dialog->get_files();
            if (files) {
                guint n_files = g_list_model_get_n_items(files->gobj());
                for (guint i = 0; i < n_files; i++) {
                    GFile* gfile = G_FILE(g_list_model_get_item(files->gobj(), i));
                    if (gfile) {
                        gchar* path = g_file_get_path(gfile);
                        if (path) {
                            add_file_to_list(path, false);
                            g_free(path);
                        }
                        g_object_unref(gfile);
                    }
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_add_folder_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择要压缩的文件夹", *this,
                                                 Gtk::FileChooser::Action::SELECT_FOLDER, "选择", "取消");

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    add_file_to_list(path, true);
                    g_free(path);
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_remove_file_clicked(const std::string &path) {
    for (auto it = m_file_list.begin(); it != m_file_list.end(); ++it) {
        if (it->path == path) {
            if (it->row) {
                m_file_list_box_widget.remove(*it->row);
            }
            append_to_log("移除: " + path + "\n");
            m_file_list.erase(it);

            m_file_counter = 0;
            for (auto &item : m_file_list) {
                m_file_counter++;
                if (item.index_label) {
                    item.index_label->set_text(std::to_string(m_file_counter));
                }
            }

            update_compress_command_display();
            break;
        }
    }
}

void GraphicalCompressionEncryptionToolWindow::on_compression_output_file_button_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择输出文件", *this, Gtk::FileChooser::Action::SAVE, "选择", "取消");

    auto filter = Gtk::FileFilter::create();
    if (m_current_mode == Mode::RAR_COMPRESS) {
        filter->add_pattern("*.rar");
        filter->set_name("RAR压缩文件 (*.rar)");
    } else {
        filter->add_pattern("*.7z");
        filter->set_name("7z压缩文件 (*.7z)");
    }
    dialog->add_filter(filter);

    std::string default_name = m_archive_base_name + (m_current_mode == Mode::RAR_COMPRESS ? ".rar" : ".7z");
    dialog->set_current_name(default_name);

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    m_compression_output_entry.set_text(path);
                    append_to_log("设置输出文件: " + std::string(path) + "\n");
                    g_free(path);
                    update_compress_command_display();
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_compression_output_directory_button_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择输出目录", *this,Gtk::FileChooser::Action::SELECT_FOLDER, "选择", "取消");

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    std::string output_dir = path;
                    std::string full_path = output_dir + "/" + m_archive_base_name + 
                                          (m_current_mode == Mode::RAR_COMPRESS ? ".rar" : ".7z");
                    m_compression_output_entry.set_text(full_path);
                    append_to_log("设置输出路径: " + full_path + "\n");
                    g_free(path);
                    update_compress_command_display();
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_archive_button_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择压缩包", *this, Gtk::FileChooser::Action::OPEN, "选择", "取消");

    auto filter = Gtk::FileFilter::create();
    filter->add_pattern("*.rar");
    filter->add_pattern("*.7z");
    filter->add_pattern("*.zip");
    filter->add_pattern("*.7z.001");
    filter->add_pattern("*.tar");
    filter->add_pattern("*.gz");
    filter->add_pattern("*.bz2");
    filter->add_pattern("*.xz");
    filter->add_pattern("*.tar.gz");
    filter->add_pattern("*.tar.bz2");
    filter->add_pattern("*.tar.xz");
    filter->add_pattern("*.tgz");
    filter->add_pattern("*.tbz2");
    filter->add_pattern("*.txz");
    filter->add_pattern("*.iso");
    filter->add_pattern("*.cab");
    filter->add_pattern("*.arj");
    filter->set_name("压缩文件 (rar, 7z, zip, tar, gz, bz2, xz, tgz, tbz2, txz, iso, cab, arj)");
    dialog->add_filter(filter);

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    m_archive_entry.set_text(path);
                    append_to_log(std::string("选择压缩包: ") + path + "\n");
                    g_free(path);
                    update_extract_command_display();
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_extract_path_button_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择解压目录", *this, Gtk::FileChooser::Action::SELECT_FOLDER, "选择", "取消");

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    m_extract_path_entry.set_text(path);
                    append_to_log(std::string("设置解压目录: ") + path + "\n");
                    g_free(path);
                    update_extract_command_display();
                }
            }
        } });
    dialog->show();
}

// ========== 密码显示切换函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_show_compression_password_toggled() {
    if (m_show_compression_password_button.get_active()) {
        m_compression_password_entry.set_visibility(true);
        m_show_compression_password_button.set_label("隐藏密码");
    } else {
        m_compression_password_entry.set_visibility(false);
        m_show_compression_password_button.set_label("显示密码");
    }
}

void GraphicalCompressionEncryptionToolWindow::on_show_extract_password_toggled() {
    if (m_show_extract_password_button.get_active()) {
        m_extract_password_entry.set_visibility(true);
        m_show_extract_password_button.set_label("隐藏密码");
    } else {
        m_extract_password_entry.set_visibility(false);
        m_show_extract_password_button.set_label("显示密码");
    }
}

void GraphicalCompressionEncryptionToolWindow::on_show_text_encryption_password_toggled() {
    if (m_show_text_encryption_password_button.get_active()) {
        m_text_encryption_password_entry.set_visibility(true);
        m_show_text_encryption_password_button.set_label("隐藏密码");
    } else {
        m_text_encryption_password_entry.set_visibility(false);
        m_show_text_encryption_password_button.set_label("显示密码");
    }
}

// ========== 命令显示函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_show_compression_command_clicked() {
    update_compress_command_display();
    std::string display_command = build_command(
        m_current_mode == Mode::RAR_COMPRESS ? CommandType::RAR_COMPRESS : CommandType::SEVENZ_COMPRESS, true);
    append_to_log("已刷新压缩命令: " + display_command + "\n");
}

void GraphicalCompressionEncryptionToolWindow::on_show_extract_command_clicked() {
    update_extract_command_display();
    append_to_log("已经刷新解压相关命令于文本框\n");
}

// ========== 文件名乱码修复函数 ==========

std::string GraphicalCompressionEncryptionToolWindow::get_safe_display_path(const std::string& path, bool is_directory) {
    std::filesystem::path p(path);
    
    if (p == p.root_path()) {
        if (is_directory) {
            return p.string() + "{可能乱码目录名安全屏蔽}";
        } else {
            std::string ext = p.extension().string();
            return p.string() + "{可能乱码文件名安全屏蔽}" + ext;
        }
    } else {
        std::string base_path = p.parent_path().string();
        if (base_path.empty()) {
            base_path = ".";
        }
        
        if (is_directory) {
            return base_path + "/{可能乱码目录名安全屏蔽}";
        } else {
            std::string ext = p.extension().string();
            return base_path + "/{可能乱码文件名安全屏蔽}" + ext;
        }
    }
}

void GraphicalCompressionEncryptionToolWindow::on_select_file_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择待转码文件名的单个文件", *this, Gtk::FileChooser::Action::OPEN, "选择", "取消");

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    m_actual_fix_path = path;
                    std::string safe_display_path = get_safe_display_path(path, false);
                    m_filename_fix_entry.set_text(safe_display_path);
                    append_to_log(std::string("选择待转码文件: ") + safe_display_path + "\n");
                    g_free(path);
                    update_filename_fix_info();
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::on_select_directory_clicked() {
    auto dialog = Gtk::FileChooserNative::create("选择待转码文件名的批量文件目录", *this,
                                                 Gtk::FileChooser::Action::SELECT_FOLDER, "选择", "取消");

    dialog->signal_response().connect([this, dialog](int response_id) {
        if (response_id == Gtk::ResponseType::ACCEPT) {
            auto file = dialog->get_file();
            if (file) {
                GFile* gfile = file->gobj();
                gchar* path = g_file_get_path(gfile);
                if (path) {
                    m_actual_fix_path = path;
                    std::string safe_display_path = get_safe_display_path(path, true);
                    m_filename_fix_entry.set_text(safe_display_path);
                    append_to_log(std::string("选择待转码目录: ") + safe_display_path + "\n");
                    g_free(path);
                    update_filename_fix_info();
                }
            }
        } });
    dialog->show();
}

void GraphicalCompressionEncryptionToolWindow::update_filename_fix_info() {
    std::string path = m_actual_fix_path;
    if (path.empty()) {
        m_filename_fix_info_buffer->set_text("");
        return;
    }

    if (access(path.c_str(), F_OK) != 0) {
        m_filename_fix_info_buffer->set_text("路径不存在");
        return;
    }

    std::stringstream info;
    
    if (access(path.c_str(), W_OK) == 0) {
        struct stat path_stat;
        if (stat(path.c_str(), &path_stat) == 0) {
            if (S_ISDIR(path_stat.st_mode)) {
                int file_count = 0;
                int dir_count = 0;
                int writable_file_count = 0;
                int writable_dir_count = 0;
                
                DIR* dir = opendir(path.c_str());
                if (dir == nullptr) {
                    info << "该目录：\n无法打开目录。";
                } else {
                    struct dirent* entry;
                    while ((entry = readdir(dir)) != nullptr) {
                        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                            continue;

                        std::string full_path = path + "/" + entry->d_name;
                        struct stat entry_stat;
                        if (stat(full_path.c_str(), &entry_stat) == 0) {
                            if (S_ISDIR(entry_stat.st_mode)) {
                                dir_count++;
                                if (access(full_path.c_str(), W_OK) == 0) {
                                    writable_dir_count++;
                                }
                            } else {
                                file_count++;
                                if (access(full_path.c_str(), W_OK) == 0) {
                                    writable_file_count++;
                                }
                            }
                        }
                    }
                    closedir(dir);

                    info << "此目录下，初步判断：\n共有" << file_count << "个文件，" << dir_count << "个文件夹(可能包含更多文件或目录)，"
                         << "其中有可写权限" << writable_file_count << "个文件，" << writable_dir_count << "个文件夹(可能包含更多文件或目录)，"
                         << "我们将逐层逐个尝试修正全部名称为UTF-8编码正确显示(包括此目录名称)。该算法简体/繁体中文编码均支持。测试分析7z解压后文件发现，7z会将非UTF-8编码名称进行某种¨转换¨操作，目前仅特征分析其部分变换规律，推荐使用rar或其它工具解压后修正编码，若失败建议使用convmv处理。";
                }
            } else {
                info << "该文件：\n存在且拥有可写权限，文件大小" << path_stat.st_size << "，我们将尝试修正名称为UTF-8编码正确显示。该算法简体/繁体中文编码均支持。测试分析7z解压后文件发现，7z会将非UTF-8编码名称进行某种¨转换¨操作，目前仅特征分析其部分变换规律，推荐使用rar或其它工具解压后修正编码，若失败建议使用convmv处理。";
            }
        }
    } else {
        info << "警告：\n路径不可写，无法进行文件名修复操作。";
    }
    
    m_filename_fix_info_buffer->set_text(info.str());
}

void GraphicalCompressionEncryptionToolWindow::on_start_fix_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }

    std::string path = m_actual_fix_path;
    if (path.empty()) {
        append_to_log("错误: 请先选择文件或目录\n", true);
        return;
    }

    if (!validate_path_security(path)) {
        append_to_log("错误: 路径包含不安全字符\n", true);
        return;
    }

    if (access(path.c_str(), W_OK) != 0) {
        append_to_log("错误: 路径不可写，请选择其他路径\n", true);
        return;
    }

    m_processing = true;
    append_to_log("开始文件名乱码修复...\n");
    
    m_select_file_button.set_sensitive(false);
    m_select_directory_button.set_sensitive(false);
    m_start_fix_button.set_sensitive(false);
    m_mode_combo.set_sensitive(false);

    m_background_processor->fix_filenames_encoding(path);
}

// ========== 文本加密解密函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_text_encrypt_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }

    if (m_text_encryption_password_entry.get_text().empty()) {
        append_to_log("错误: 请输入加密密码\n", true);
        return;
    }

    std::string plaintext = m_plaintext_buffer->get_text();
    if (plaintext.empty()) {
        append_to_log("错误: 请输入要加密的文本\n", true);
        return;
    }

    std::string password = m_text_encryption_password_entry.get_text();
    std::string cipher_mode = m_text_cipher_mode_combo.get_active_text();
    std::string kdf = m_text_kdf_combo.get_active_text();

    m_processing = true;
    m_text_encrypt_button.set_sensitive(false);
    m_text_decrypt_button.set_sensitive(false);

    append_to_log("准备开始文本加密操作...\n");
    append_to_log("使用加密算法模式: " + cipher_mode + ", 密钥派生方式: " + kdf + "\n");

    m_background_processor->encrypt_text(plaintext, password, cipher_mode, kdf);
}

void GraphicalCompressionEncryptionToolWindow::on_text_decrypt_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }

    if (m_text_encryption_password_entry.get_text().empty()) {
        append_to_log("错误: 请输入解密密码\n", true);
        return;
    }

    std::string ciphertext = m_ciphertext_buffer->get_text();
    if (ciphertext.empty()) {
        append_to_log("错误: 请输入要解密的文本\n", true);
        return;
    }

    std::string password = m_text_encryption_password_entry.get_text();
    std::string cipher_mode = m_text_cipher_mode_combo.get_active_text();
    std::string kdf = m_text_kdf_combo.get_active_text();

    m_processing = true;
    m_text_encrypt_button.set_sensitive(false);
    m_text_decrypt_button.set_sensitive(false);

    append_to_log("准备开始文本解密操作...\n");
    append_to_log("使用加密算法模式: " + cipher_mode + ", 密钥派生方式: " + kdf + "\n");

    m_background_processor->decrypt_text(ciphertext, password, cipher_mode, kdf);
}

// ========== 控件变化响应函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_compression_password_changed() {
    std::string password = m_compression_password_entry.get_text();
    int current_selection = m_compression_encryption_type_combo.get_active_row_number();

    if (password.empty()) {
        if (current_selection != 0) {
            m_compression_encryption_type_combo.set_active(0);
        }
    } else {
        if (current_selection == 0) {
            m_compression_encryption_type_combo.set_active(1);
        }
    }
    update_compress_command_display();
}

void GraphicalCompressionEncryptionToolWindow::on_volume_changed() {
    std::string volume = m_volume_entry.get_text();
    bool valid_format = true;
    bool valid_value = true;

    if (!volume.empty()) {
        valid_format = validate_volume_format(volume);
        valid_value = validate_volume_value(volume);

        if (!valid_format) {
            append_to_log("警告: 分卷大小格式无效，请输入如256K/32M/1G的格式\n", true);
        } else if (!valid_value) {
            append_to_log("错误: 分卷大小不能为0值（如0K/0M/0G等）\n", true);
        }
    }

    bool overall_valid = volume.empty() || (valid_format && valid_value);
    set_control_validation(m_volume_entry, overall_valid);
    if (overall_valid) {
        update_compress_command_display();
    }
}

void GraphicalCompressionEncryptionToolWindow::on_compression_output_changed() {
    std::string output = m_compression_output_entry.get_text();
    bool valid = validate_compression_output_path(output);

    set_control_validation(m_compression_output_entry, valid);
    if (!valid && !output.empty()) {
        if (!validate_path_security(output)) {
            append_to_log("错误: 输出路径包含不安全字符\n", true);
        } else if (!validate_compression_output_extension(output)) {
            std::string expected_ext = (m_current_mode == Mode::RAR_COMPRESS) ? ".rar" : ".7z";
            append_to_log("错误: 输出文件扩展名必须是" + expected_ext + "\n", true);
        } else if (access(std::filesystem::path(output).parent_path().string().c_str(), W_OK) != 0) {
            append_to_log("错误: 输出目录不可写，请选择其他目录\n", true);
        }
    }

    // 更新压缩包基础名称
    if (!output.empty()) {
        std::filesystem::path output_path(output);
        if (output_path.has_filename()) {
            m_archive_base_name = output_path.stem().string();
        }
    }

    if (valid && !output.empty()) {
        update_compress_command_display();
    }
}

void GraphicalCompressionEncryptionToolWindow::on_extract_path_changed() {
    std::string path = m_extract_path_entry.get_text();
    bool valid = validate_extract_path(path);

    set_control_validation(m_extract_path_entry, valid);
    if (!valid && !path.empty()) {
        if (!validate_path_security(path)) {
            append_to_log("错误: 解压目录路径包含不安全字符\n", true);
        } else if (access(path.c_str(), W_OK) != 0) {
            append_to_log("错误: 解压目录不可写，请选择其他目录\n", true);
        }
    }

    if (valid && !path.empty()) {
        update_extract_command_display();
    }
}

// ========== 命令行构建函数 ==========

std::string GraphicalCompressionEncryptionToolWindow::build_command(CommandType type, bool for_display) {
    switch (type) {
        case CommandType::RAR_COMPRESS: return build_rar_compress_command_inline(for_display);
        case CommandType::SEVENZ_COMPRESS: return build_7z_compress_command_inline(for_display);
        case CommandType::RAR_LIST_FILES: return build_rar_list_files_command_inline(for_display);
        case CommandType::SEVENZ_LIST_FILES: return build_7z_list_files_command_inline(for_display);
        case CommandType::UNZIP_LIST_FILES: return build_unzip_list_files_command_inline(for_display);
        case CommandType::RAR_TEST_INTEGRITY: return build_rar_test_integrity_command_inline(for_display);
        case CommandType::SEVENZ_TEST_INTEGRITY: return build_7z_test_integrity_command_inline(for_display);
        case CommandType::UNZIP_TEST_INTEGRITY: return build_unzip_test_integrity_command_inline(for_display);
        case CommandType::RAR_GET_COMMENT: return build_rar_get_comment_command_inline(for_display);
        case CommandType::SEVENZ_GET_COMMENT: return build_7z_get_comment_command_inline(for_display);
        case CommandType::UNZIP_GET_COMMENT: return build_unzip_get_comment_command_inline(for_display);
        case CommandType::RAR_EXTRACT: return build_rar_extract_command_inline(for_display);
        case CommandType::SEVENZ_EXTRACT: return build_7z_extract_command_inline(for_display);
        case CommandType::UNZIP_EXTRACT: return build_unzip_extract_command_inline(for_display);
        default: return "";
    }
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_rar_compress_command_inline(bool for_display) {
    std::stringstream cmd;
    cmd << "rar a";

    std::string compression_level = get_compression_level_value();
    if (!compression_level.empty()) {
        cmd << " " << compression_level;
    }

    std::string password = m_compression_password_entry.get_text();
    int encryption_type = m_compression_encryption_type_combo.get_active_row_number();
    if (!password.empty() && encryption_type > 0) {
        if (encryption_type == 1) {
            cmd << " -p" << (for_display ? "***" : "'" + password + "'");
        } else if (encryption_type == 2) {
            cmd << " -hp" << (for_display ? "***" : "'" + password + "'");
        }
    }

    std::string volume = m_volume_entry.get_text();
    if (!volume.empty() && validate_volume_format(volume) && validate_volume_value(volume)) {
        cmd << " -v" << convert_volume_to_lower(volume);
    }

    std::string dict_size = get_dict_size_value();
    if (!dict_size.empty()) {
        cmd << " -md" << dict_size;
    }

    std::string comment_text = m_compression_comment_buffer->get_text();
    if (!comment_text.empty()) {
        std::string output_path = m_compression_output_entry.get_text();
        if (!output_path.empty()) {
            std::string comment_file = std::filesystem::path(output_path).parent_path().string() + "/压缩包注释tmp.txt";
            cmd << " -z'" << comment_file << "'";
        }
    }

    if (m_solid_checkbutton.get_active()) {
        cmd << " -s";
    } else {
        cmd << " -s-";
    }
    cmd << " -ep1 -k -y";

    std::string output_file = m_compression_output_entry.get_text();
    if (!output_file.empty()) {
        cmd << " '" << output_file << "'";
    }

    for (const auto &file : m_file_list) {
        cmd << " '" << file.path << "'";
    }

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_7z_compress_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string tool_name = m_7zz_available ? "7zz" : "7z";
    cmd << tool_name << " a -t7z";

    std::string compression_level = get_compression_level_value();
    if (!compression_level.empty()) {
        cmd << " " << compression_level;
    }

    cmd << " -mmt";

    std::string dict_size = get_dict_size_value();
    if (!dict_size.empty()) {
        cmd << " -md" << dict_size;
    }

    std::string word_size = get_word_size_value();
    if (!word_size.empty()) {
        cmd << " -mfb" << word_size;
    }

    if (m_solid_checkbutton.get_active()) {
        cmd << " -ms=on";
    } else {
        cmd << " -ms=off";
    }

    std::string password = m_compression_password_entry.get_text();
    int encryption_type = m_compression_encryption_type_combo.get_active_row_number();
    if (!password.empty() && encryption_type > 0) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
        if (encryption_type == 2) {
            cmd << " -mhe=on";
        }
    }

    std::string volume = m_volume_entry.get_text();
    if (!volume.empty() && validate_volume_format(volume) && validate_volume_value(volume)) {
        cmd << " -v" << convert_volume_to_lower(volume);
    }

    cmd << " -y";

    std::string output_file = m_compression_output_entry.get_text();
    if (!output_file.empty()) {
        cmd << " '" << output_file << "'";
    }

    for (const auto &file : m_file_list) {
        cmd << " '" << file.path << "'";
    }

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_rar_list_files_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "rar l";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_7z_list_files_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    std::string tool_name = m_7zz_available ? "7zz" : "7z";
    cmd << tool_name << " l";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_unzip_list_files_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "unzip -l";
    if (!password.empty()) {
        cmd << " -P" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_rar_test_integrity_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "rar t";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_7z_test_integrity_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    std::string tool_name = m_7zz_available ? "7zz" : "7z";
    cmd << tool_name << " t";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_unzip_test_integrity_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "unzip -t";
    if (!password.empty()) {
        cmd << " -P" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_rar_get_comment_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "rar cw";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "' /dev/stdout";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_7z_get_comment_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    std::string tool_name = m_7zz_available ? "7zz" : "7z";
    cmd << tool_name << " l -slt";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "' | grep Comment";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_unzip_get_comment_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "unzip -z";
    if (!password.empty()) {
        cmd << " -P" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " '" << archive_path << "'";

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_rar_extract_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string extract_path = m_extract_path_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "rar x";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    if (!extract_path.empty()) {
        cmd << " '" << extract_path << "'";
    }

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_7z_extract_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string extract_path = m_extract_path_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    std::string tool_name = m_7zz_available ? "7zz" : "7z";
    cmd << tool_name << " x";
    if (!password.empty()) {
        cmd << " -p" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " -y '" << archive_path << "'";

    if (!extract_path.empty()) {
        cmd << " -o'" << extract_path << "'";
    }

    return cmd.str();
}

inline std::string GraphicalCompressionEncryptionToolWindow::build_unzip_extract_command_inline(bool for_display) {
    std::stringstream cmd;
    std::string archive_path = m_archive_entry.get_text();
    std::string extract_path = m_extract_path_entry.get_text();
    std::string password = m_extract_password_entry.get_text();

    cmd << "unzip";
    if (!password.empty()) {
        cmd << " -P" << (for_display ? "***" : "'" + password + "'");
    }
    cmd << " '" << archive_path << "'";

    if (!extract_path.empty()) {
        cmd << " -d '" << extract_path << "'";
    }

    return cmd.str();
}

void GraphicalCompressionEncryptionToolWindow::update_compress_command_display() {
    std::string display_command;
    if (m_current_mode == Mode::RAR_COMPRESS) {
        display_command = build_command(CommandType::RAR_COMPRESS, true);
    } else if (m_current_mode == Mode::SEVENZ_COMPRESS) {
        display_command = build_command(CommandType::SEVENZ_COMPRESS, true);
    } else {
        display_command = "";
    }
    m_compression_command_entry.set_text(display_command);
}

void GraphicalCompressionEncryptionToolWindow::update_extract_command_display() {
    int tool_index = m_extract_tool_combo.get_active_row_number();
    
    std::stringstream commands;
    
    switch (tool_index) {
        case 0: {
            commands << "解压文件: " << build_command(CommandType::RAR_EXTRACT, true) << "\n";
            commands << "测试文件: " << build_command(CommandType::RAR_TEST_INTEGRITY, true) << "\n";
            commands << "列出文件: " << build_command(CommandType::RAR_LIST_FILES, true) << "\n";
            commands << "获取注释: " << build_command(CommandType::RAR_GET_COMMENT, true);
            break;
        }
        case 1: {
            commands << "解压文件: " << build_command(CommandType::SEVENZ_EXTRACT, true) << "\n";
            commands << "测试文件: " << build_command(CommandType::SEVENZ_TEST_INTEGRITY, true) << "\n";
            commands << "列出文件: " << build_command(CommandType::SEVENZ_LIST_FILES, true) << "\n";
            commands << "获取注释: " << build_command(CommandType::SEVENZ_GET_COMMENT, true);
            break;
        }
        case 2: {
            commands << "解压文件: " << build_command(CommandType::UNZIP_EXTRACT, true) << "\n";
            commands << "测试文件: " << build_command(CommandType::UNZIP_TEST_INTEGRITY, true) << "\n";
            commands << "列出文件: " << build_command(CommandType::UNZIP_LIST_FILES, true) << "\n";
            commands << "获取注释: " << build_command(CommandType::UNZIP_GET_COMMENT, true);
            break;
        }
    }
    
    m_extract_command_buffer->set_text(commands.str());
}

// ========== 工具函数 ==========

std::string GraphicalCompressionEncryptionToolWindow::get_compression_level_value() {
    int level_index = m_compression_level_combo.get_active_row_number();
    if (m_current_mode == Mode::RAR_COMPRESS) {
        switch (level_index) {
            case 1: return "-m4";
            case 2: return "-m5";
            default: return "";
        }
    } else {
        switch (level_index) {
            case 1: return "-mx8";
            case 2: return "-mx9";
            default: return "";
        }
    }
}

std::string GraphicalCompressionEncryptionToolWindow::get_dict_size_value() {
    int dict_index = m_dict_size_combo.get_active_row_number();
    if (dict_index >= 0) {
        std::string dict_text = m_dict_size_combo.get_active_text();
        std::string dict_value = dict_text;
        if (dict_value.find("MB") != std::string::npos) {
            dict_value = dict_value.substr(0, dict_value.length() - 2) + "m";
        } else if (dict_value.find("GB") != std::string::npos) {
            dict_value = dict_value.substr(0, dict_value.length() - 2) + "g";
        }
        return dict_value;
    }
    return "";
}

std::string GraphicalCompressionEncryptionToolWindow::get_word_size_value() {
    int word_index = m_word_size_combo.get_active_row_number();
    if (word_index >= 0) {
        return m_word_size_combo.get_active_text();
    }
    return "";
}

bool GraphicalCompressionEncryptionToolWindow::validate_volume_format(const std::string &volume) {
    if (volume.empty()) {
        return true;
    }

    if (volume.length() < 2) {
        return false;
    }

    char last_char = static_cast<char>(std::tolower(static_cast<unsigned char>(volume.back())));
    std::string number_part = volume.substr(0, volume.length() - 1);

    if (last_char != 'b' && last_char != 'k' && last_char != 'm' && last_char != 'g' && last_char != 't') {
        return false;
    }

    for (char c : number_part) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    try {
        std::stoull(number_part);
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

std::string GraphicalCompressionEncryptionToolWindow::convert_volume_to_lower(const std::string &volume) {
    if (volume.empty()) {
        return volume;
    }
    std::string result = volume;
    result[result.length() - 1] = static_cast<char>(std::tolower(static_cast<unsigned char>(result[result.length() - 1])));
    return result;
}

void GraphicalCompressionEncryptionToolWindow::create_comment_file(const std::string &output_path) {
    std::string comment_text = m_compression_comment_buffer->get_text();
    if (!comment_text.empty()) {
        std::string comment_file = std::filesystem::path(output_path).parent_path().string() + "/压缩包注释tmp.txt";
        std::ofstream file(comment_file, std::ios::out | std::ios::binary);
        if (file.is_open()) {
            file << "\xEF\xBB\xBF" << comment_text;
            file.close();
            append_to_log("创建注释文件: " + comment_file + "\n");
        } else {
            append_to_log("错误: 无法创建注释文件\n", true);
        }
    }
}

bool GraphicalCompressionEncryptionToolWindow::validate_volume_value(const std::string &volume) {
    if (volume.empty()) {
        return true;
    }
    std::string number_part = volume.substr(0, volume.length() - 1);
    try {
        unsigned long long value = std::stoull(number_part);
        if (value == 0) {
            return false;
        }
    } catch (const std::exception &) {
        return false;
    }
    return true;
}

inline bool GraphicalCompressionEncryptionToolWindow::validate_path_security(const std::string &path) {
    if (path.empty()) {
        return false;
    }

    if (path.find("/../") != std::string::npos ||
        path.find("/./") != std::string::npos ||
        path.find("\\..\\") != std::string::npos ||
        path.find("\\.\\") != std::string::npos ||
        path.find("..") == 0 ||
        path.find("../") == 0 ||
        path.find("~") == 0) {
        return false;
    }

    if (path.find("//") != std::string::npos ||
        path.find("\\\\") != std::string::npos) {
        return false;
    }

    if (path == "." || path == "./") {
        return false;
    }

    return true;
}

bool GraphicalCompressionEncryptionToolWindow::validate_compression_output_path(const std::string &path) {
    if (path.empty()) {
        return false;
    }

    if (!validate_path_security(path)) {
        return false;
    }

    std::string output_dir = std::filesystem::path(path).parent_path().string();
    if (access(output_dir.c_str(), W_OK) != 0) {
        return false;
    }

    if (!validate_compression_output_extension(path)) {
        return false;
    }

    return true;
}

bool GraphicalCompressionEncryptionToolWindow::validate_extract_path(const std::string &path) {
    if (path.empty()) {
        return false;
    }

    if (!validate_path_security(path)) {
        return false;
    }

    if (access(path.c_str(), W_OK) != 0) {
        return false;
    }

    return true;
}

bool GraphicalCompressionEncryptionToolWindow::validate_compression_output_extension(const std::string &path) {
    if (path.empty()) {
        return false;
    }
    std::filesystem::path p(path);
    std::string extension = p.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    if (m_current_mode == Mode::RAR_COMPRESS) {
        return extension == ".rar";
    } else if (m_current_mode == Mode::SEVENZ_COMPRESS) {
        return extension == ".7z";
    }
    return true;
}

// ========== 输入验证函数 ==========

std::string GraphicalCompressionEncryptionToolWindow::validate_compress_inputs() {
    if (m_file_list.empty()) {
        return "请先添加要压缩的文件或文件夹";
    }

    std::string output = m_compression_output_entry.get_text();
    if (output.empty()) {
        return "输出文件路径不能为空";
    }
    
    if (!validate_path_security(output)) {
        return "输出路径包含不安全字符";
    }

    if (!validate_compression_output_extension(output)) {
        std::string expected_ext = (m_current_mode == Mode::RAR_COMPRESS) ? ".rar" : ".7z";
        return "输出文件扩展名必须是" + expected_ext;
    }

    std::string output_dir = std::filesystem::path(output).parent_path().string();
    if (access(output_dir.c_str(), W_OK) != 0) {
        return "输出目录不可写，请选择其他目录";
    }

    std::string volume = m_volume_entry.get_text();
    if (!volume.empty()) {
        if (!validate_volume_format(volume)) {
            return "分卷大小格式无效，请输入如256K/32M/1G的格式";
        }
        if (!validate_volume_value(volume)) {
            return "分卷大小不能为0值（如0K/0M/0G等）";
        }
    }

    return ""; // 空字符串表示验证通过
}

std::string GraphicalCompressionEncryptionToolWindow::validate_extract_inputs() {
    if (m_archive_entry.get_text().empty()) {
        return "请先选择压缩包";
    }

    std::string extract_path = m_extract_path_entry.get_text();
    if (extract_path.empty()) {
        return "解压目录不能为空";
    }
    
    if (!validate_path_security(extract_path)) {
        return "解压目录路径包含不安全字符";
    }

    if (access(extract_path.c_str(), W_OK) != 0) {
        return "解压目录不可写，请选择其他目录";
    }

    return ""; // 空字符串表示验证通过
}

// ========== 操作执行函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_start_compress_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }

    //验证函数，获取具体错误信息
    std::string validation_error = validate_compress_inputs();
    if (!validation_error.empty()) {
        append_to_log("压缩验证失败: " + validation_error + "\n", true);
        return;
    }

    if (m_current_mode == Mode::RAR_COMPRESS) {
        std::string comment_text = m_compression_comment_buffer->get_text();
        if (!comment_text.empty()) {
            create_comment_file(m_compression_output_entry.get_text());
        }
    }

    m_processing = true;
    append_to_log("开始压缩操作...\n");
    
    std::string display_command = build_command(
        m_current_mode == Mode::RAR_COMPRESS ? CommandType::RAR_COMPRESS : CommandType::SEVENZ_COMPRESS, true);
    append_to_log("执行命令: " + display_command + "\n");
    
    m_start_compress_button.set_sensitive(false);
    m_mode_combo.set_sensitive(false);

    std::string actual_command = build_command(
        m_current_mode == Mode::RAR_COMPRESS ? CommandType::RAR_COMPRESS : CommandType::SEVENZ_COMPRESS, false);

    if (m_current_mode == Mode::RAR_COMPRESS) {
        m_background_processor->compress_with_rar(actual_command, m_compression_output_entry.get_text());
    } else {
        m_background_processor->compress_with_7z(actual_command, m_compression_output_entry.get_text());
    }
}

void GraphicalCompressionEncryptionToolWindow::on_test_integrity_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }
    if (m_archive_entry.get_text().empty()) {
        append_to_log("错误: 请先选择压缩包\n", true);
        return;
    }

    m_processing = true;
    append_to_log("测试压缩包完整性: " + m_archive_entry.get_text() + "\n");

    int tool_index = m_extract_tool_combo.get_active_row_number();
    std::string actual_command, display_command;
    CommandType command_type;
    
    switch (tool_index) {
        case 0: command_type = CommandType::RAR_TEST_INTEGRITY; break;
        case 1: command_type = CommandType::SEVENZ_TEST_INTEGRITY; break;
        case 2: command_type = CommandType::UNZIP_TEST_INTEGRITY; break;
        default: command_type = CommandType::RAR_TEST_INTEGRITY; break;
    }
    
    actual_command = build_command(command_type, false);
    display_command = build_command(command_type, true);
    
    append_to_log("执行命令: " + display_command + "\n");
    std::string tool = (tool_index == 0) ? "rar" : (tool_index == 1) ? "7z" : "unzip";
    m_background_processor->test_archive_integrity(actual_command, tool);
}

void GraphicalCompressionEncryptionToolWindow::on_list_files_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }
    if (m_archive_entry.get_text().empty()) {
        append_to_log("错误: 请先选择压缩包\n", true);
        return;
    }

    m_processing = true;
    append_to_log("列出压缩包文件: " + m_archive_entry.get_text() + "\n");

    int tool_index = m_extract_tool_combo.get_active_row_number();
    std::string actual_command, display_command;
    CommandType command_type;
    
    switch (tool_index) {
        case 0: command_type = CommandType::RAR_LIST_FILES; break;
        case 1: command_type = CommandType::SEVENZ_LIST_FILES; break;
        case 2: command_type = CommandType::UNZIP_LIST_FILES; break;
        default: command_type = CommandType::RAR_LIST_FILES; break;
    }
    
    actual_command = build_command(command_type, false);
    display_command = build_command(command_type, true);
    
    append_to_log("执行命令: " + display_command + "\n");
    std::string tool = (tool_index == 0) ? "rar" : (tool_index == 1) ? "7z" : "unzip";
    m_background_processor->list_archive_contents(actual_command, tool);
}

void GraphicalCompressionEncryptionToolWindow::on_get_comment_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }
    if (m_archive_entry.get_text().empty()) {
        append_to_log("错误: 请先选择压缩包\n", true);
        return;
    }

    m_processing = true;
    append_to_log("获取压缩包注释: " + m_archive_entry.get_text() + "\n");

    int tool_index = m_extract_tool_combo.get_active_row_number();
    std::string actual_command, display_command;
    CommandType command_type;
    
    switch (tool_index) {
        case 0: command_type = CommandType::RAR_GET_COMMENT; break;
        case 1: command_type = CommandType::SEVENZ_GET_COMMENT; break;
        case 2: command_type = CommandType::UNZIP_GET_COMMENT; break;
        default: command_type = CommandType::RAR_GET_COMMENT; break;
    }
    
    actual_command = build_command(command_type, false);
    display_command = build_command(command_type, true);
    
    append_to_log("执行命令: " + display_command + "\n");
    std::string tool = (tool_index == 0) ? "rar" : (tool_index == 1) ? "7z" : "unzip";
    m_background_processor->get_archive_comment(actual_command, tool);
}

void GraphicalCompressionEncryptionToolWindow::on_start_extract_clicked() {
    if (m_processing) {
        append_to_log("警告: 操作执行中...\n", false);
        return;
    }

    //验证函数，获取具体错误信息
    std::string validation_error = validate_extract_inputs();
    if (!validation_error.empty()) {
        append_to_log("解压验证失败: " + validation_error + "\n", true);
        return;
    }

    m_processing = true;
    append_to_log("开始解压操作...\n");

    int tool_index = m_extract_tool_combo.get_active_row_number();
    std::string actual_command, display_command;
    CommandType command_type;
    
    switch (tool_index) {
        case 0: command_type = CommandType::RAR_EXTRACT; break;
        case 1: command_type = CommandType::SEVENZ_EXTRACT; break;
        case 2: command_type = CommandType::UNZIP_EXTRACT; break;
        default: command_type = CommandType::RAR_EXTRACT; break;
    }

    actual_command = build_command(command_type, false);
    display_command = build_command(command_type, true);

    append_to_log("执行命令: " + display_command + "\n");
    m_start_extract_button.set_sensitive(false);
    m_mode_combo.set_sensitive(false);

    switch (tool_index) {
        case 0: m_background_processor->extract_with_rar(actual_command, m_archive_entry.get_text()); break;
        case 1: m_background_processor->extract_with_7z(actual_command, m_archive_entry.get_text()); break;
        case 2: m_background_processor->extract_with_unzip(actual_command, m_archive_entry.get_text()); break;
    }
}

// ========== 后台处理回调函数 ==========

void GraphicalCompressionEncryptionToolWindow::on_rar7z_operation_completed(const std::string &result, bool success) {
    Glib::signal_idle().connect_once([this, result, success]() {
        if (success) {
            append_to_log("操作完成\n");
        } else {
            append_to_log("操作失败\n", true);
        }
        append_to_log(result + "\n");
        m_start_compress_button.set_sensitive(true);
        m_start_extract_button.set_sensitive(true);
        m_mode_combo.set_sensitive(true);
        m_processing = false; });
}

void GraphicalCompressionEncryptionToolWindow::on_text_encryption_completed(const std::string &result, bool success, bool is_encryption) {
    Glib::signal_idle().connect_once([this, result, success, is_encryption]() {
        if (success) {
            append_to_log(is_encryption ? "加密完成\n" : "解密完成\n");
            
            if (is_encryption) {
                m_ciphertext_buffer->set_text(result);
            } else {
                m_plaintext_buffer->set_text(result);
            }
        } else {
            append_to_log(is_encryption ? "加密失败\n" : "解密失败\n", true);
        }
        append_to_log(result + "\n");
        m_text_encrypt_button.set_sensitive(true);
        m_text_decrypt_button.set_sensitive(true);
        m_processing = false; });
}

void GraphicalCompressionEncryptionToolWindow::on_filename_fix_completed(const std::string &result, bool success) {
    Glib::signal_idle().connect_once([this, result, success]() {
        if (success) {
            append_to_log("文件名乱码修复完成\n");
        } else {
            append_to_log("文件名乱码修复失败\n", true);
        }
        append_to_log(result + "\n");
        m_select_file_button.set_sensitive(true);
        m_select_directory_button.set_sensitive(true);
        m_start_fix_button.set_sensitive(true);
        m_mode_combo.set_sensitive(true);
        m_processing = false; });
}

void GraphicalCompressionEncryptionToolWindow::on_progress_update(const std::string &message) {
    Glib::signal_idle().connect_once([this, message]() { 
        append_to_log(message + "\n"); });
}

// ========== 工具检测函数 ==========

void GraphicalCompressionEncryptionToolWindow::check_tools_async() {
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        check_rar_version();
        std::this_thread::sleep_for(std::chrono::milliseconds(125));
        check_7z_version(); }).detach();
}

void GraphicalCompressionEncryptionToolWindow::check_rar_version() {
    try {
        std::string output;
        std::string error;
        int exit_status = 0;

        Glib::spawn_command_line_sync("rar", &output, &error, &exit_status);

        Glib::signal_idle().connect_once([this, output, error, exit_status]() {
            if (exit_status == 0 || exit_status == 7) {
                m_rar_available = true;
                append_to_log("rar工具检测成功\n");
                std::string version_info;
                size_t version_pos = output.find("RAR ");
                if (version_pos != std::string::npos) {
                    size_t end_pos = output.find('\n', version_pos);
                    if (end_pos != std::string::npos) version_info = output.substr(version_pos, end_pos - version_pos);
                    else version_info = output.substr(version_pos);
                    append_to_log("rar版本: " + version_info + "\n");
                } else {
                    std::istringstream stream(output);
                    std::string line;
                    int line_count = 0;
                    while (std::getline(stream, line) && line_count < 3) {
                        if (!line.empty()) {
                            append_to_log("rar信息: " + line + "\n");
                            line_count++;
                        }
                    }
                }
            } else {
                m_rar_available = false;
                append_to_log("rar工具检测失败，若使用RAR功能,请检查rar工具...\n", true);
                if (!error.empty()) append_to_log("错误信息: " + error + "\n", true);
            }
            update_extract_tool_default(); });
    } catch (const Glib::Error &e) {
        Glib::signal_idle().connect_once([this, e]() { 
            m_rar_available = false;
            append_to_log(std::string("rar工具检测异常: ") + e.what() + "\n", true); 
            update_extract_tool_default();
        });
    }
}

void GraphicalCompressionEncryptionToolWindow::check_7z_version() {
    m_7zz_available = false;
    m_7z_available = false;
    
    auto check_tool = [this](const std::string& tool_name, bool& available_flag) -> bool {
        try {
            std::string output;
            std::string error;
            int exit_status = 0;

            Glib::spawn_command_line_sync(tool_name, &output, &error, &exit_status);

            if (exit_status == 0 || exit_status == 7) {
                available_flag = true;
                
                Glib::signal_idle().connect_once([this, tool_name, output]() {
                    append_to_log(tool_name + "工具检测成功\n");
                    std::string version_info;
                    size_t version_pos = output.find("7-Zip");
                    if (version_pos != std::string::npos) {
                        size_t end_pos = output.find('\n', version_pos);
                        if (end_pos != std::string::npos) version_info = output.substr(version_pos, end_pos - version_pos);
                        else version_info = output.substr(version_pos);
                        append_to_log(tool_name + "版本: " + version_info + "\n");
                    } else {
                        std::istringstream stream(output);
                        std::string line;
                        int line_count = 0;
                        while (std::getline(stream, line) && line_count < 3) {
                            if (!line.empty()) {
                                append_to_log(tool_name + "信息: " + line + "\n");
                                line_count++;
                            }
                        }
                    }
                });
                return true;
            }
        } catch (const Glib::Error &e) {
        }
        return false;
    };

    check_tool("7zz", m_7zz_available);
    check_tool("7z", m_7z_available);

    if (!m_7zz_available && !m_7z_available) {
        Glib::signal_idle().connect_once([this]() { 
            append_to_log("7z工具检测失败: 未找到环境中的7zz和7z\n", true); 
        });
    }
    
    Glib::signal_idle().connect_once([this]() {
        update_extract_tool_default();
    });
}

void GraphicalCompressionEncryptionToolWindow::update_extract_tool_default() {
    if (m_7zz_available || m_7z_available) {
        m_extract_tool_combo.set_active(1);
    } else if (m_rar_available) {
        m_extract_tool_combo.set_active(0);
    } else {
        m_extract_tool_combo.set_active(2);
    }
}

void GraphicalCompressionEncryptionToolWindow::update_extract_tool_by_archive(const std::string& archive_path) {
    if (archive_path.empty()) {
        return;
    }
    
    std::filesystem::path p(archive_path);
    std::string extension = p.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    if (extension == ".rar" && m_rar_available) {
        m_extract_tool_combo.set_active(0);
    } else {
        update_extract_tool_default();
    }
}

// ========== 日志和辅助函数 ==========

void GraphicalCompressionEncryptionToolWindow::append_to_log(const std::string &text, bool is_error) {
    auto end_iter = m_log_buffer->end();
    std::string timestamp = get_current_time();
    std::string log_entry = "[" + timestamp + "]" + (is_error ? "[ERROR] " : "[INFO] ") + text;

    m_log_buffer->insert(end_iter, log_entry);

    auto mark = m_log_buffer->create_mark("end", m_log_buffer->end());
    m_log_textview.scroll_to(mark);
}

std::string GraphicalCompressionEncryptionToolWindow::get_current_time() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y/%m/%d %H:%M:%S");
    return oss.str();
}

void GraphicalCompressionEncryptionToolWindow::set_control_validation(Gtk::Widget &widget, bool valid) {
    auto style_context = widget.get_style_context();
    if (valid) {
        style_context->remove_class("error");
    } else {
        style_context->add_class("error");
    }
}

void GraphicalCompressionEncryptionToolWindow::show_help_dialog() {
    auto dialog = new Gtk::Dialog("图形化压缩加密辅助工具帮助", *this);
    dialog->set_default_size(600, 600);
    dialog->set_modal(true);

    auto scrolled_window = Gtk::make_managed<Gtk::ScrolledWindow>();
    scrolled_window->set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
    scrolled_window->set_vexpand(true);

    auto text_view = Gtk::make_managed<Gtk::TextView>();
    text_view->set_editable(false);
    text_view->set_cursor_visible(false);
    text_view->set_wrap_mode(Gtk::WrapMode::WORD);
    text_view->get_buffer()->set_text(help_contents);

    scrolled_window->set_child(*text_view);
    dialog->get_content_area()->append(*scrolled_window);

    dialog->add_button("关闭", Gtk::ResponseType::OK);
    dialog->set_default_response(Gtk::ResponseType::OK);

    dialog->signal_response().connect([dialog](int /* response_id */) { 
        delete dialog; 
    });

    dialog->show();
}

int main(int argc, char *argv[]) {
    auto app = Gtk::Application::create("com.unix-like.tool");

    auto css_provider = Gtk::CssProvider::create();
    const char *css_data = R"CSS(
        .error { 
            color: red;
            border-color: red;
        }
        .warning {
            color: orange;
            border-color: orange;
        }
        .blue-button {
            background: linear-gradient(to bottom, #1e90ff, #0066cc);
            color: white;
            font-weight: bold;
            border: 2px solid #004499;
            border-radius: 5px;
            padding: 8px 16px;
        }
        .blue-button:hover {
            background: linear-gradient(to bottom, #3ca0ff, #0080ff);
            color: white;
        }
        .blue-button:active {
            background: linear-gradient(to bottom, #0066cc, #004499);
            color: white;
        }
    )CSS";

    css_provider->load_from_data(css_data);
    Gtk::StyleContext::add_provider_for_display(
        Gdk::Display::get_default(),
        css_provider,
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    return app->make_window_and_run<GraphicalCompressionEncryptionToolWindow>(argc, argv);
}

const Glib::ustring GraphicalCompressionEncryptionToolWindow::help_contents(R"(
            图形化压缩加密辅助工具 v3.1

🎯 工具简介
    本工具是一款面向 Linux 平台用户的图形化压缩文件管理辅助软件，致力于辅助您解决命令行压缩操作中输入复杂、参数繁琐的痛点。软件基于系统环境中已安装的 RAR 与 7z 命令行工具实现核心压缩功能，为用户提供接近 Windows 平台 WinRAR 与 7-Zip 的图形化操作体验。同时，近期增加了文件名编码转化UTF-8的功能，极大解决了旧版Windows的压缩文件在Linux系统文件名称错乱的问题。此外，文本加密功能就作为添头，贻笑大方了。

============================================
                依赖安装指南
============================================
本工具需要系统中已安装 RAR 和 7z 命令行工具才能正常运行。

方法一：使用系统包管理器安装（推荐）
【Ubuntu/Debian 系统】
RAR安装：sudo apt install rar unrar
7z安装：sudo apt install p7zip-full p7zip-rar

【CentOS/RHEL 系统】
首先启用EPEL仓库：sudo yum install epel-release
sudo yum install rar unrar && sudo yum install p7zip p7zip-plugins

【Fedora 系统】
sudo dnf install rar unrar && sudo dnf install p7zip

【Arch Linux/Manjaro 系统】
sudo pacman -S rar && sudo pacman -S p7zip

方法二：从官网下载二进制包安装
【RAR 安装步骤】
1. 访问 RARLAB 官网：https://www.rarlab.com/download.htm
2. 下载 Linux 版本（64位系统下载 rarlinux-x64-*.tar.gz）
3. 解压：tar -xvf rarlinux-x64-*.tar.gz
4. 进入目录：cd rar
5. 安装：sudo make install 或手动复制：sudo cp rar unrar /usr/local/bin/

【7z 安装步骤】
1. 访问 7-Zip 官网：https://www.7-zip.org
2. 下载对应版本的源码或二进制包
3. 按照官网说明编译安装或手动复制：sudo cp 7zz /usr/local/bin/

🔥 热点问题

为什么专注 RAR 和 7z，而未支持 ZIP？

我经过多方面评估，决定不内置 ZIP 格式支持。主要原因如下：

1. ZIP 的使用场景与本工具定位不符  
   ZIP 作为一种较为早期的压缩格式，已被多数操作系统原生支持。其典型使用场景通常不涉及加密、分卷、注释等高级功能，更多仅用于基本打包或临时传输。因此，对于 ZIP 这类参数选项有限、系统已有图形化工具支持的格式，使用命令行辅助工具的必要性不大。

2. 暂时没有 ZIP 压缩需求  
   如你对 ZIP 格式有强制性的使用需求，欢迎与我联系，我可能会根据实际情况增改源码。

3. ZIP 在安全性与功能完整性上存在不足  
   作为一款面向 Linux 桌面用户的压缩辅助工具，我更推荐使用 RAR 与 7z 格式，它们具有明显优势：

安全性对比：
- RAR 与 7z：采用现代 AES-256 加密标准，安全性高
- ZIP：传统 ZipCrypto 存在已知漏洞，易被暴力破解

功能完整性对比：
- ❌ ZIP 压缩率一般 | ✅ RAR、7z 提供极高压缩率
- ❌ ZIP 大文件处理资源占用高 | ✅ RAR、7z 资源占用优化良好
- ❌ ZIP 字典固定为 32KB/64KB | ✅ RAR、7z 支持自定义 GB 级字典
- ❌ ZIP 注释功能初级受限 | ✅ RAR 提供完整注释支持（最大 64KB）
- ❌ ZIP 分卷支持不完善 | ✅ RAR、7z 支持智能分卷压缩
- ❌ ZIP 仅支持加密文件内容 | ✅ RAR、7z 支持加密文件内容及文件名

📝 版本历史

3.1版本：
    较3.0版本，增加了文件名批量转化UTF-8编码功能，微调了界面，重构整理部分旧有代码，增强可维护性同时使其更符合我的操作习惯，修复一些无关紧要的小bug。该版本解决了我的某段工作中领导发送的Windows7下生成压缩包，与我使用操作系统的编码不匹配，而导致的文件名乱码问题。

3.0版本：
    目前的版本定为3.0，是因为我最初编写了仅支持RAR压缩的1.0版本，后来却发现rar工具解压的格式兼容性、多样性不如7z工具，于是着手编写了支持7z与RAR的2.0版本；但代码量增加后发现设计存在问题，最终抛弃旧代码重新编写了目前的3.0版本。这也是例如操作过程中为什么没有滑动条动画效果，为什么没有过于严格的输入检查的原因。另一方面，事实上，在功能上，我目前并未找到7z添加注释的方式。如果不考虑RAR商业闭源可能存后门的情况，7z在密码学上的文件加密安全性是未必高于rar5的，比如7z的密钥派生未使用盐值。因此，建议两个工具配合使用。

🛠️ 常见问题
Q: 压缩/解压过程中界面无响应？
A: 此为正常现象。压缩任务运行在后台线程中，任务完成后将自动恢复响应，因为是调用工具执行操作，不便中止，请勿中途退出。

Q: 如何确保压缩文件的安全性？
A: 建议加密压缩包内的文件名和文件内容，并设置高强度密码，避免使用简单或常见密码。

💡 使用提示
- 处理大文件前，请确保磁盘有足够剩余空间
- 处理大文件时，请耐心等待操作完成
- 程序会自动清理临时文件

📞 联系我
如有问题或建议，欢迎通过以下方式联系：
- B站：好梦总被尿憋醒噶
感谢您使用及认可我的图形化辅助工具！

                                2025年11月
)");

const Glib::ustring GraphicalCompressionEncryptionToolWindow::plaintext_contents(R"(这里输入/输出明文文本内容，请清空后在此输入明文内容!
示例文本:

────────────────────────────────────────
  安全需求         密钥派生方式        加密算法模式          适用场景
────────────────────────────────────────
  最高安全     Scrypt N=2²⁰ r=8 p=1    AES-256-GCM          敏感数据、长期存储、
                                    或 AES-256-CBC+HMAC   抗量子计算预备、
                                                        政府机构、军事应用

  平衡安全     PBKDF2 + SHA3-256       AES-256-GCM          企业数据、个人隐私、
    (默认)   或 PBKDF2 + BLAKE2S-256   (推荐)              金融信息、医疗记录、
                 320,000次迭代                          知识产权保护

  性能优先     PBKDF2 + SHA-256        AES-256-GCM          移动设备、实时通信、
                 320,000次迭代        (推荐)              临时数据、批量处理、
                                                        性能敏感环境
────────────────────────────────────────

附：
文本加密解密技术文档
====================

1. 概述
--------
本系统实现基于OpenSSL的对称加密算法，支持AES-256-GCM和AES-256-CBC + HMAC两种加密模式，
支持多种密钥派生方式，包括Scrypt和PBKDF2，迭代次数32万次，支持SHA256、SHA3-256、BLAKE2S-256三种哈希函数。

2. 加密流程
-----------
输入: 明文 + 密码 + 加密算法模式 + 密钥派生方式
输出: Base64编码的密文字符串

┌───────────────────────────────┐
│                          加密流程                            │
└───────────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  生成随机盐值   │ 16字节随机数据
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  密钥派生       │ 根据选择的密钥派生方式
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  生成随机IV     │ AES-GCM:12字节, AES-CBC:16字节
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  执行加密操作   │ 使用选定算法加密明文
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  完整性保护     │ GCM模式:认证标签, CBC模式:HMAC
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  组合数据块     │ 盐值 + IV + 密文 + 完整性保护数据
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  Base64编码     │ 输出最终密文字符串
└───────────────────────────┘

3. 解密流程
-----------
输入: Base64密文 + 密码 + 加密算法模式 + 密钥派生方式
输出: 原始明文字符串

┌───────────────────────────────┐
│                          解密流程                            │
└───────────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  Base64解码     │ 还原二进制数据
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  解析数据块     │ 分离盐值、IV、密文、完整性保护数据
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  密钥派生       │ 使用相同参数重新派生密钥
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  完整性验证     │ GCM模式:验证认证标签, CBC模式:验证HMAC
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  执行解密操作   │ 使用密钥和IV解密密文
└───────────────────────────┘
         │
         ▼
┌───────────────────────────┐
│  输出明文       │ UTF-8编码的明文字符串
└───────────────────────────┘

4. 技术规格
-----------

4.1 加密算法模式参数:
├─ AES-256-GCM
│  ├─ 密钥长度: 32字节 (256位)
│  ├─ IV长度: 12字节
│  ├─ 认证标签: 16字节
│  └─ 块大小: 16字节
│
└─ AES-256-CBC + HMAC
   ├─ 加密密钥长度: 32字节 (256位)
   ├─ HMAC密钥长度: 32字节 (256位)
   ├─ IV长度: 16字节
   ├─ HMAC长度: 32字节
   └─ 块大小: 16字节

4.2 密钥派生方式参数:
├─ Scrypt
│  ├─ N: 1048576 (2^20)
│  ├─ r: 8
│  ├─ p: 1
│  └─ 最大内存: 8GB
│
├─ PBKDF2 + SHA-256 | 320,000
│  ├─ 算法: PBKDF2
│  ├─ 迭代次数: 320,000次
│  ├─ 盐值长度: 16字节
│  └─ 哈希函数: SHA-256
│
├─ PBKDF2 + SHA3-256 | 320,000
│  ├─ 算法: PBKDF2
│  ├─ 迭代次数: 320,000次
│  ├─ 盐值长度: 16字节
│  └─ 哈希函数: SHA3-256
│
└─ PBKDF2 + BLAKE2S-256 | 320,000
   ├─ 算法: PBKDF2
   ├─ 迭代次数: 320,000次
   ├─ 盐值长度: 16字节
   └─ 哈希函数: BLAKE2S-256

5. 数据块结构详细说明
--------------------

5.1 AES-256-GCM模式:
┌────────────┬─────────┬───────┬──
│  盐值      │   IV     │    加密数据      │  认证标签    │
│  16字节    │  12字节  │  变长(明文长度)  │   16字节     │
└────────────┴─────────┴───────┴──

5.2 AES-256-CBC + HMAC模式:
┌────────────┬─────────┬───────┬──
│  盐值      │   IV     │    加密数据      │    HMAC      │
│  16字节    │  16字节  │  变长(明文长度)  │   32字节     │
└────────────┴─────────┴───────┴──

6. 关键函数伪代码
-----------------

6.1 加密函数:
function encrypt(plaintext, password, cipher_mode, kdf):
    salt = generate_random_bytes(16)
    
    if kdf contains "Scrypt":
        key = scrypt(password, salt, N=1048576, r=8, p=1, maxmem=8GB)
    else:
        if kdf contains "SHA-256": hash_func = "SHA256"
        if kdf contains "SHA3-256": hash_func = "SHA3-256" 
        if kdf contains "BLAKE2S-256": hash_func = "BLAKE2S-256"
        key = pbkdf2(password, salt, hash_func, 320000, key_length)
    
    if cipher_mode == "AES-256-GCM":
        iv = generate_random_bytes(12)
        cipher = EVP_aes_256_gcm()
        # 执行加密...
        tag = get_authentication_tag(16)
        final_data = salt + iv + encrypted_data + tag
    else: # AES-256-CBC + HMAC
        iv = generate_random_bytes(16)
        cipher = EVP_aes_256_cbc()
        # 分离加密密钥和HMAC密钥
        encryption_key = key[0:32]
        hmac_key = key[32:64]
        # 执行加密...
        # 计算HMAC(IV + 加密数据)
        hmac = compute_hmac(iv + encrypted_data, hmac_key, hash_func)
        final_data = salt + iv + encrypted_data + hmac
    
    return base64_encode(final_data)

6.2 解密函数:
function decrypt(ciphertext_base64, password, cipher_mode, kdf):
    final_data = base64_decode(ciphertext_base64)
    
    if cipher_mode == "AES-256-GCM":
        salt = final_data[0:16]
        iv = final_data[16:28]
        encrypted_data = final_data[28:-16]
        tag = final_data[-16:]
    else: # AES-256-CBC + HMAC
        salt = final_data[0:16]
        iv = final_data[16:32]
        encrypted_data = final_data[32:-32]
        hmac = final_data[-32:]
    
    # 密钥派生（与加密相同）
    if kdf contains "Scrypt":
        key = scrypt(password, salt, N=1048576, r=8, p=1, maxmem=8GB)
    else:
        # 根据kdf确定哈希函数
        key = pbkdf2(password, salt, hash_func, 320000, key_length)
    
    if cipher_mode == "AES-256-GCM":
        set_authentication_tag(tag)
        plaintext = decrypt_with_algorithm(encrypted_data, key, iv, cipher)
        verify_authentication_tag()
    else: # AES-256-CBC + HMAC
        # 分离密钥
        encryption_key = key[0:32]
        hmac_key = key[32:64]
        # 验证HMAC
        if not verify_hmac(iv + encrypted_data, hmac, hmac_key, hash_func):
            throw "HMAC验证失败"
        plaintext = decrypt_with_algorithm(encrypted_data, encryption_key, iv, cipher)
    
    return plaintext

7. 性能和安全考虑
----------------

7.1 内存使用:
├─ Scrypt密钥派生: 约1GB内存峰值使用
├─ 其他密钥派生方式: 内存使用可忽略
└─ 总体设计: 支持8GB以上内存设备

7.2 安全强度:
├─ AES-256-GCM: 提供加密和完整性保护
├─ AES-256-CBC + HMAC: 加密和完整性保护分离
├─ Scrypt: 抗ASIC/GPU攻击的内存硬函数
└─ PBKDF2: 经过充分验证的标准

8. 跨平台实现要点
----------------

8.1 内存管理:
- Scrypt需要充足内存，确保系统有足够可用内存
- 大内存分配后及时释放，避免内存泄漏
- 考虑在内存受限环境下的降级方案

8.2 关键参数一致性:
- 必须保持各参数严格一致
- Scrypt参数固定为N=2^20, r=8, p=1
- PBKDF2迭代次数固定为32万次

9. 错误处理
----------

9.1 常见错误情况:
- Scrypt内存分配失败
- HMAC验证失败（数据被篡改）
- 密码错误导致解密失败
- Base64格式错误

9.2 错误标识:
- 明确区分密码错误和数据完整性错误
- 内存分配失败应提供适当错误信息
- 保持错误信息的用户友好性

10. 安全建议
-----------

10.1 密钥派生选择:
- 高安全需求: 使用Scrypt（抗暴力破解）
- 兼容性需求: 使用PBKDF2 + SHA3-256
- 性能敏感: 使用PBKDF2 + SHA-256

10.2 加密模式选择:
- 推荐使用AES-256-GCM（性能更好）
- AES-256-CBC + HMAC提供密钥分离优势

11. 兼容性说明
--------------

本加密系统与以下标准兼容:
- RFC 2898 (PBKDF2)
- RFC 7914 (Scrypt)
- RFC 4648 (Base64)
- NIST SP 800-38D (GCM模式)
- NIST SP 800-38A (CBC模式)
- OpenSSL加密实现

12. 紧急恢复流程
---------------

如果原程序不可用，可按以下步骤手动解密:

1. 获取Base64密文、密码和使用的参数组合
2. 使用兼容的加密库(如OpenSSL, BouncyCastle)
3. 特别注意Scrypt的内存参数设置
4. 按照本文档的技术规格实现解密函数
5. 验证解密结果的正确性

技术参考:
- OpenSSL文档: https://www.openssl.org/docs/
- Scrypt标准: RFC 7914
- PBKDF2标准: RFC 2898
- AES-GCM标准: NIST SP 800-38D
)");
const Glib::ustring GraphicalCompressionEncryptionToolWindow::ciphertext_contents(R"(这里输入/输出密文文本内容，请清空后此输入密文内容! 
必须提醒您，"保密系统不应依赖于算法的保密，而应仅依赖于密钥的保密。")	——克劳德·香农
)");