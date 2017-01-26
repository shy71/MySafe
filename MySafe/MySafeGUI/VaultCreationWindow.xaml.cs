using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
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
    /// Interaction logic for VaultCreationWindow.xaml
    /// </summary>
    public partial class VaultCreationWindow : Window
    {
        FileVault vault;
        public VaultCreationWindow()
        {
            InitializeComponent();
        }
        public VaultCreationWindow(FileVault v)
        {
            InitializeComponent();
            vault = v;
            filePath_Click(null, null);            
        }
        string path = "";
        private void Create_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (path == "")
                    throw new Exception("The path is empty");
                if (masterPassword.GetText() == null)
                    throw new Exception("The master password field is empty");
                vault.CreateVault(path, masterPassword.GetText());
                MessageBox.Show("The Vault has been opened successfully.\n" + path, "Vault Opened", MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.OK);
                this.Close();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }
        private void filePath_Click(object sender, RoutedEventArgs e)
        {
            var saveFile = new SaveFileDialog();
            saveFile.DefaultExt = "vlt";
            saveFile.AddExtension = true;
            saveFile.Filter = "Vault Files(*.vlt) | *.vlt|All Files(*.*) | *.*";
            saveFile.ShowDialog();
            path = saveFile.FileName;
            if (path.Length > 0)
            {
                filePath.ToolTip = path;
                filePath.Text = System.IO.Path.GetFileName(path);
                createBtn.IsEnabled = true;
            }
            else
            {
                filePath.ToolTip = "Press to Choose path";
                filePath.Text = "Path: No path was chosen";
                createBtn.IsEnabled = false;

            }
        }
        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
