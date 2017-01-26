using System;
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
using System.IO;
using System.Windows.Shapes;
using MySafe_Adapter;
using Microsoft.Win32;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for LoadVaultWindow.xaml
    /// </summary>
    public partial class LoadVaultWindow : Window
    {
        FileVault vault;
        string path;
        public LoadVaultWindow(FileVault v)
        {
            InitializeComponent();
            vault = v;
            filePath_Click(null, null);

        }
        public LoadVaultWindow()
        {
            InitializeComponent();
        }

        private void filePath_Click(object sender, RoutedEventArgs e)
        {
            var openFile = new OpenFileDialog();
            openFile.DefaultExt = "vlt";
            openFile.AddExtension = true;
            openFile.Filter = "Vault Files(*.vlt) | *.vlt|All Files(*.*) | *.*";
            openFile.ShowDialog();
            path = openFile.FileName;
            if (path.Length > 0)
            {
                filePath.ToolTip = path;
                filePath.Text = System.IO.Path.GetFileName(path);
                openBtn.IsEnabled = true;
            }
            else
            {
                filePath.ToolTip = "Press to Choose vault file";
                filePath.Text = "Path: No file was chosen";
                openBtn.IsEnabled = false;

            }
        }

        private void Open_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (path == "")
                    throw new Exception("No Vault File was chosen");
                if (masterPassword.GetText() == null)
                    throw new Exception("The master password field is empty");
                vault.LoadVault(path, masterPassword.GetText());
                MessageBox.Show("The Vault has been opened successfully.\n" + path, "Vault Opened", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
                this.Close();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }
    }
}
