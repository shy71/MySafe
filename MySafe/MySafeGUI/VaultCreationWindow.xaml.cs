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
        }
        string FileDir = "";
        private void Done_Click(object sender, RoutedEventArgs e)
        {
            if(FileDir == "")
            {
                MessageBox.Show("You must enter a directory path for the vault", "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                return;
            }
            //create vault
            try
            {
                vault.CreateVault(FileDir, masterPassword.Text);
            }
            catch(Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                return;
            }

            MessageBox.Show("The vault has been created successfully.", "Vault Created", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
        }

        private void vaultDirectory_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();

            if (result == System.Windows.Forms.DialogResult.OK)
                FileDir = dialog.SelectedPath;
            vaultDirectory.Text = FileDir;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
