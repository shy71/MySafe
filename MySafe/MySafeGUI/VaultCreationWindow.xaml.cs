using System;
using System.Windows;
using MySafe_Adapter;
using Microsoft.Win32;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for VaultCreationWindow.xaml
    /// </summary>
    public partial class VaultCreationWindow : Window
    {
        //Current Vault
        FileVault vault;
        //Vault File Path
        string path = "";
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
        #region Clicks Functions

        //Create Vault Click Function
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
        //File Path Click Function
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
            }
            else
            {
                filePath.ToolTip = "Press to Choose path";
                filePath.Text = "Path: No path was chosen";

            }
        }
        #endregion

    }
}
