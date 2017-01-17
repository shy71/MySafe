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
    /// Interaction logic for EncryptionWindow.xaml
    /// </summary>
    public partial class EncryptionWindow : Window
    {
        public string FileName { get; set; }
        public EncryptionWindow()
        {
            InitializeComponent();
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();

            if (result == System.Windows.Forms.DialogResult.OK)
                FileName = dialog.SelectedPath;
            FilePathTxt.Text = FileName;
        }


        private void EncryptFileBtn_Click(object sender, RoutedEventArgs e)
        {
            FileStream theFile = new FileStream(FileName, FileMode.Open);
            byte[] arr = new byte[theFile.Length];
            int length = theFile.Read(arr,0,(int)theFile.Length);
            StringBuilder plaintext = new StringBuilder();
            foreach (byte b in arr)
            {
                plaintext.Append(b);
            }
            File.Delete(FileName);
            System.Security.SecureString password = passwordBox.SecurePassword;
            string cipherFileName = "";



            string ciphertext="";//= encrypted text of file
                                 //send the password and 



            for (int i = FileName.Length - 1; i >= 0 ; i--)
            {
                if(FileName[i] == '.')
                {
                    cipherFileName = FileName.Substring(0, i);
                    break;
                }
            }
            cipherFileName += ".ens";
            FileStream cipherFile = new FileStream(cipherFileName, FileMode.CreateNew);
            byte[] cipherBytes = Encoding.ASCII.GetBytes(ciphertext);
            cipherFile.Write(cipherBytes, 0, cipherBytes.Length);
            cipherFile.Close();
            theFile.Close();            
        }

        private void CancelBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
