using System;
using System.Collections.Generic;
using System.IO;
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
using System.Windows.Navigation;
using System.Windows.Shapes;

using MySafe_Adapter;
namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        FileVault vault = null;
        public MainWindow()
        {
            InitializeComponent();
            Directory.SetCurrentDirectory("../../../Simulation");
            vault = new FileVault();

        }
        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {

            try
            {
                if (!vault.isVaultOpen())
                    throw new Exception("There is no open vault at the moment to encrypt with");
                //open pop-up window for choosing file and encrypting it
                new EncryptionWindow(vault).ShowDialog();
            }
            catch(Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!vault.isVaultOpen())
                    throw new Exception("There is no open vault at the moment to decrypt with");
                new DecryptionWindow(vault).ShowDialog();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }

        private void Information_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("This program is an Intel SGX based program in charge of encrypting files in a way \n"
                            + "that it is secure when trying to decrypt it from a different computer.\n"
                            + "For example, if a file was encrypted on a certain machine, there is no way to decrypt it on another machine, \neven if all the code and the data of the first machine is compromised.\n\n"
                            + "WARNING! \nThis program only works on computers that support Intel SGX.",
                            "Description", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
        }

        private void CreateVault_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (vault.isVaultOpen())
                    throw new Exception("There is already an open vault! please close it before opening a new one!");
                new VaultCreationWindow(vault).ShowDialog();
            }
            catch(Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                vault = null;
            }
            finally
            {
                if (vault.isVaultOpen())
                {
                    openVault.Text = vault.FileName;
                    openVault.ToolTip = vault.FilePath;
                }
            }
        }

        private void LoadVault_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (vault.isVaultOpen())
                    throw new Exception("There is already an open vault! please close it before opening a new one!");
                new LoadVaultWindow(vault).ShowDialog();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                vault = null;
            }
            finally
            {
                if (vault.isVaultOpen())
                {
                    openVault.Text = vault.FileName;
                    openVault.ToolTip = vault.FilePath;
                }
            }
        }

        private void CloseVault_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!vault.isVaultOpen())
                    throw new Exception("There isn't any open vault to close!");
                vault.CloseVault();
                MessageBox.Show("The Vault has been closed successfully.\n" + vault.FilePath, "Vault Closed", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                vault = null;
            }
            finally
            {
                if (vault.isVaultOpen())
                {
                    openVault.Text = vault.FileName;
                    openVault.ToolTip = vault.FilePath;
                }
            }
        }
    }
}
