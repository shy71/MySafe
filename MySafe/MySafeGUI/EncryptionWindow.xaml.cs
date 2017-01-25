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
using MySafe_Adapter;
using Microsoft.Win32;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for EncryptionWindow.xaml
    /// </summary>
    public partial class EncryptionWindow : Window
    {
        FileVault vault;
        string srcPath;
        string destPath;
        public EncryptionWindow(FileVault v)
        {
            InitializeComponent();
            vault = v;
            OpenfilePath_Click(null, null);
            
        }
        public EncryptionWindow()
        {
            InitializeComponent();
        }

        private void OpenfilePath_Click(object sender, RoutedEventArgs e)
        {
            var openFile = new OpenFileDialog();
            openFile.DefaultExt = "vlt";
            openFile.AddExtension = true;
            openFile.Filter = "Vault Files(*.vlt) | *.vlt;";
            openFile.ShowDialog();
            srcPath = openFile.FileName;
            if (srcPath.Length > 0)
            {
                openFilePath.ToolTip = srcPath;
                openFilePath.Text = System.IO.Path.GetFileName(srcPath);
                if (destPath.Length == 0)
                {
                    destPath = System.IO.Path.GetDirectoryName(srcPath) + System.IO.Path.GetFileNameWithoutExtension(srcPath) + ".ens";
                    saveFilePath.ToolTip = destPath;
                    saveFilePath.Text = System.IO.Path.GetFileName(destPath);
                }
            }
            else
            {
                openFilePath.ToolTip = "Press to Choose vault file";
                openFilePath.Text = "No file was choosen";
            }
        }
        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            vault.EncryptFile(srcPath, destPath, password.GetText());
        }

        private void SavefilePath_Click(object sender, RoutedEventArgs e)
        {
            var saveFile = new SaveFileDialog();
            saveFile.DefaultExt = "vlt";
            saveFile.AddExtension = true;
            saveFile.Filter = "Encrypted Files(*.ens) | *.ens;";
            saveFile.ShowDialog();
            destPath = saveFile.FileName;
            if (destPath.Length > 0)
            {
                saveFilePath.ToolTip = destPath;
                saveFilePath.Text = System.IO.Path.GetFileName(destPath);
            }
            else
            {
                saveFilePath.ToolTip = "Press to Choose vault file";
                saveFilePath.Text = "No file was choosen";
            }
        }
    }
}
