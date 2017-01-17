using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for DecryptionWindow.xaml
    /// </summary>
    public partial class DecryptionWindow : Window
    {
        public string FileName { get; set; }
        public DecryptionWindow()
        {
            InitializeComponent();
        }

        private void DecryptFileBtn_Click(object sender, RoutedEventArgs e)
        {
            FileStream theFile = new FileStream(FileName, FileMode.Open);
            byte[] arr = new byte[theFile.Length];
            int length = theFile.Read(arr, 0, (int)theFile.Length);
            StringBuilder ciphertext = new StringBuilder();
            foreach (byte b in arr)
            {
                ciphertext.Append(b);
            }
            File.Delete(FileName);
            System.Security.SecureString password = passwordBox.SecurePassword;
            System.Security.SecureString masterpassword = materPasswordBox.SecurePassword;
            string plainFileName = "";



            string plaintext = "";//= decrypted text of file
                                  //send the password and masterpassword
            plainFileName = plainFileName.Substring(0, plainFileName.Length); 
            plainFileName += suffix.Text;
            FileStream plainFile = new FileStream(plainFileName, FileMode.CreateNew);
            byte[] plainBytes = Encoding.ASCII.GetBytes(plaintext);
            plainFile.Write(plainBytes, 0, plainBytes.Length);
            plainFile.Close();
            theFile.Close();
        }

        private void CancelBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();

            if (result == System.Windows.Forms.DialogResult.OK)
                FileName = dialog.SelectedPath;
            FilePathTxt.Text = FileName;

        }
    }
}
