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
using System.Windows.Shapes;
using MySafe_Adapter;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for LoadVaultWindow.xaml
    /// </summary>
    public partial class LoadVaultWindow : Window
    {
        FileVault vault;
        public LoadVaultWindow(FileVault v)
        {
            InitializeComponent();
            vault = v;
        }
        public LoadVaultWindow()
        {
            InitializeComponent();
        }

        private void vaultDirectoryBtn_Click(object sender, RoutedEventArgs e)
        {
            string FileName = "";
            System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dialog.ShowDialog();

            if (result == System.Windows.Forms.DialogResult.OK)
                FileName = dialog.SelectedPath;
            vaultDirectory.Text = FileName;
        }

        private void Done_Click(object sender, RoutedEventArgs e)
        {
            vault.LoadVault(vaultDirectory.Text, masterPassword.Text);
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
