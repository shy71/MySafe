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
                vault.CreateVault(FileDir, masterPassword.GetText());
            }
            catch(Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                return;
            }

            MessageBox.Show("The vault has been created successfully.", "Vault Created", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
            this.Close();
        }

        private void vaultDirectory_Click(object sender, RoutedEventArgs e)
        {
            var openFile = new SaveFileDialog();
            openFile.DefaultExt = "vlt";
            openFile.AddExtension = true;
            openFile.Filter = "Vault Files(*.vlt) | *.vlt;";
            openFile.ShowDialog();
            FileDir = openFile.FileName;
            vaultDirectory.SetText(FileDir);
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
