using Microsoft.Win32;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using Microsoft.Win32;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Media.Animation;
using System.IO;
using System;
namespace ac17_gui
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        [DllImport("libac17gcm.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "setup")]
        public static extern int setup(string path);

        [DllImport("libac17gcm.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "generateSecretKey")]
        public static extern int generateSecretKey(string publicKeyFile, string masterKeyFile, string attributes, string privateKeyFile);

        [DllImport("libac17gcm.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "AC17encrypt")]
        public static extern int AC17encrypt(string publicKeyFile, string plaintextFile, string policy, string ciphertextFile);


        [DllImport("libac17gcm.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "AC17decrypt")]
        public static extern int AC17decrypt(string publicKeyFile, string privateKeyFile, string ciphertextFile, string recovertextFile);

        string pathSetup = "";
        string publickeyfile = "";
        string prikeyfile = "";
        string mskeyfile = "";
        string plaintextFile = "";
        string ciphertextFile = "";
        string rcvFile = "";
        string keyformat = "";
        string pltformat = "";
        string cptformat = "";
        string rcvtformat = "";
        string mode = "";
        int keySize = 0;


        private void get_setup_directory()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Title = "Chọn một file trong thư mục";
            openFileDialog.Filter = "All files (*.*)|*.*"; // Bạn có thể tùy chỉnh filter

            // Mở hộp thoại để người dùng chọn file
            if (openFileDialog.ShowDialog() == true)
            {
                string folderPath = System.IO.Path.GetDirectoryName(openFileDialog.FileName); // Lấy thư mục của file
                pathSetup = folderPath; // Lưu đường dẫn vào biến toàn cục publickeypath
                txbpathsetup.Text = pathSetup; // Hiển thị đường dẫn trong TextBox
            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void btnReadMasterKey_Click(object sender, RoutedEventArgs e)
        {
            get_setup_directory(); // Gọi hàm để lấy đường dẫn thư mục
        }

        private void btnReadMasterKey1_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                mskeyfile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbMasterkey.Text = mskeyfile;

            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer ", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void get_publickey_file()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                publickeyfile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbPublickey.Text = publickeyfile;

            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer ", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnReadPublicKey_Click(object sender, RoutedEventArgs e)
        {
            get_publickey_file();
        }


        private void btnReadPrikey_Click(object sender, RoutedEventArgs e)
        {


            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                prikeyfile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbPrikey.Text = prikeyfile;

            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer ", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnReadPlaintext_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                plaintextFile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbPlaintext.Text = plaintextFile;

            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer ", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnCiphertext_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                ciphertextFile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbCiphertext.Text = ciphertextFile;

            }
            else
            {
                //MessageBox.Show("Không thể mở File Explorer ", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnRcvtext_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                rcvFile = filePath; // Copy đường dẫn của tệp vào clipboard
                txbRcvtext.Text = rcvFile;
            }
            else
            {
            }
        }

        private void btnSetup_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Kiểm tra xem pathSetup có hợp lệ không
                if (string.IsNullOrWhiteSpace(txbpathsetup.Text))
                {
                    MessageBox.Show("Path setup cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return; // Thoát khỏi hàm nếu pathSetup không hợp lệ
                }

                // Gọi hàm setup và lưu kết quả vào biến res
                int res = setup(pathSetup);

                // Kiểm tra kết quả của hàm setup
                if (res == 1)
                {
                    // Hiển thị thông báo thành công
                    MessageBox.Show("Setup successful!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    string content = "Master and Public key saved to: \n" + pathSetup;

                    // Xóa nội dung hiện tại của RichTextBox và thêm nội dung mới
                    rtbRes.Document.Blocks.Clear();
                    rtbRes.Document.Blocks.Add(new Paragraph(new Run(content)));
                }
                else
                {
                    // Hiển thị thông báo thất bại
                    MessageBox.Show("Setup failed!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                // Xử lý lỗi bằng cách hiển thị thông báo với thông tin chi tiết
                MessageBox.Show($"An error occurred: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void btnGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            string attributes = txbAttr.Text;

            // Kiểm tra xem attributes có hợp lệ không
            if (string.IsNullOrWhiteSpace(attributes))
            {
                MessageBox.Show("Attributes cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu attributes không hợp lệ
            }

            // Kiểm tra xem publickeyfile và mskeyfile có hợp lệ không
            if (string.IsNullOrWhiteSpace(publickeyfile))
            {
                MessageBox.Show("Public key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu publickeyfile không hợp lệ
            }

            if (string.IsNullOrWhiteSpace(mskeyfile))
            {
                MessageBox.Show("Master secret key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu mskeyfile không hợp lệ
            }

            // Kiểm tra xem prikeyfile có hợp lệ không
            if (string.IsNullOrWhiteSpace(prikeyfile))
            {
                MessageBox.Show("Private key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu prikeyfile không hợp lệ
            }

            try
            {
                // Gọi hàm generateSecretKey và lưu kết quả vào biến res
                int res = generateSecretKey(publickeyfile, mskeyfile, attributes, prikeyfile);

                // Kiểm tra kết quả của hàm generateSecretKey
                if (res == 1)
                {
                    // Hiển thị thông báo thành công
                    MessageBox.Show("Generate key successful!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    string content = "Private key saved to: \n" + prikeyfile;

                    // Xóa nội dung hiện tại của RichTextBox và thêm nội dung mới
                    rtbRes.Document.Blocks.Clear();
                    rtbRes.Document.Blocks.Add(new Paragraph(new Run(content)));
                }
                else
                {
                    // Hiển thị thông báo thất bại
                    MessageBox.Show("Generate key failed!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                // Xử lý lỗi bằng cách hiển thị thông báo với thông tin chi tiết
                MessageBox.Show($"An error occurred: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        


        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            string policy = txbPolicy.Text;

            // Kiểm tra xem policy có hợp lệ không
            if (string.IsNullOrWhiteSpace(policy))
            {
                MessageBox.Show("Policy cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu policy không hợp lệ
            }

            // Kiểm tra xem publickeyfile có hợp lệ không
            if (string.IsNullOrWhiteSpace(txbPublickey.Text))
            {
                MessageBox.Show("Public key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu publickeyfile không hợp lệ
            }

            // Kiểm tra xem plaintextFile có hợp lệ không
            if (string.IsNullOrWhiteSpace(txbPlaintext.Text))
            {
                MessageBox.Show("Plaintext file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu plaintextFile không hợp lệ
            }

            // Kiểm tra xem ciphertextFile có hợp lệ không
            if (string.IsNullOrWhiteSpace(txbCiphertext.Text))
            {
                MessageBox.Show("Ciphertext file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu ciphertextFile không hợp lệ
            }

            try
            {
                // Gọi hàm AC17encrypt và lưu kết quả vào biến res
                int res = AC17encrypt(publickeyfile, plaintextFile, policy, ciphertextFile);

                // Kiểm tra kết quả của hàm AC17encrypt
                if (res == 1)
                {
                    // Hiển thị thông báo thành công
                    MessageBox.Show("Encrypt successful!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    string content = "Ciphertext saved to: \n" + ciphertextFile;

                    // Xóa nội dung hiện tại của RichTextBox và thêm nội dung mới
                    rtbRes.Document.Blocks.Clear();
                    rtbRes.Document.Blocks.Add(new Paragraph(new Run(content)));
                }
                else
                {
                    // Hiển thị thông báo thất bại
                    MessageBox.Show("Encrypt failed!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                // Xử lý lỗi bằng cách hiển thị thông báo với thông tin chi tiết
                MessageBox.Show($"An error occurred: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // Kiểm tra xem publickeyfile, prikeyfile, và ciphertextFile có hợp lệ không
            if (string.IsNullOrWhiteSpace(txbPublickey.Text))
            {
                MessageBox.Show("Public key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu publickeyfile không hợp lệ
            }

            if (string.IsNullOrWhiteSpace(txbPrikey.Text))
            {
                MessageBox.Show("Private key file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu prikeyfile không hợp lệ
            }

            if (string.IsNullOrWhiteSpace(txbCiphertext.Text))
            {
                MessageBox.Show("Ciphertext file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu ciphertextFile không hợp lệ
            }
            if (string.IsNullOrWhiteSpace(txbRcvtext.Text))
            {
                MessageBox.Show("Recovertext file path cannot be empty!", "Cảnh báo", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // Thoát khỏi hàm nếu rcv không hợp lệ
            }
            try
            {
                // Gọi hàm AC17decrypt và lưu kết quả vào biến res
                int res = AC17decrypt(publickeyfile, prikeyfile, ciphertextFile, rcvFile);

                // Kiểm tra kết quả của hàm AC17decrypt
                if (res == 1)
                {
                    // Hiển thị thông báo thành công
                    MessageBox.Show("Decrypt successful!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    string content = "Recover text saved to: \n" + rcvFile;

                    // Xóa nội dung hiện tại của RichTextBox và thêm nội dung mới
                    rtbRes.Document.Blocks.Clear();
                    rtbRes.Document.Blocks.Add(new Paragraph(new Run(content)));
                }
                else
                {
                    // Hiển thị thông báo thất bại
                    MessageBox.Show("Decrypt failed!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
                    MessageBox.Show($"Error code: {res}", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
                    Console.WriteLine(res);
                }
            }
            catch (Exception ex)
            {
                // Xử lý lỗi bằng cách hiển thị thông báo với thông tin chi tiết
                MessageBox.Show($"An error occurred: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void rtbRes_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
    }
}