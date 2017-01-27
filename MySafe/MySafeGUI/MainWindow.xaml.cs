using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;

using MySafe_Adapter;


/*
 *Created by Ezra Block & Shy Tennenbaum
 */

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        //Current vault
        FileVault vault = null;

        public MainWindow()
        {
            InitializeComponent();
            if (!Directory.GetFiles(Directory.GetCurrentDirectory()).Any((name) => name.Contains("Bridge DLL.dll")))
                Directory.SetCurrentDirectory("../../../Output");
            vault = new FileVault();
            ClearOpenVault();

        }

        #region Clicks Functions
        //Encryption Click Function
        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {

            try
            {
                if (!vault.isVaultOpen())
                    throw new Exception("There is no open vault at the moment to encrypt with");
                //open pop-up window for choosing file and encrypting it
                new EncryptionWindow(vault).ShowDialog();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }
        //Decryption Click Function
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
        //Information Click Function
        private void Information_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("This program is an Intel SGX based program in charge of encrypting files in a way \n"
                            + "that it is secure when trying to decrypt it from a different computer.\n"
                            + "For example, if a file was encrypted on a certain machine, there is no way to decrypt it on another machine, \neven if all the code and the data of the first machine is compromised.\n\n"
                            + "WARNING! \nThis program only works on computers that support Intel SGX.",
                            "Description", MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.OK);
        }
        //Create Vault Click Function
        private void CreateVault_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (vault.isVaultOpen())
                    throw new Exception("There is already an open vault! please close it before opening a new one!");
                new VaultCreationWindow(vault).ShowDialog();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
            finally
            {
                if (vault.isVaultOpen())
                {
                    SetOpenVault();
                }
            }
        }
        //Load Vault Click Function
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
            }
            finally
            {
                if (vault.isVaultOpen())
                {
                    SetOpenVault();
                }
            }
        }
        //Close Vault Click Function
        private void CloseVault_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!vault.isVaultOpen())
                    throw new Exception("There isn't any open vault to close!");
                vault.CloseVault();
                MessageBox.Show("The Vault has been closed successfully.\n" + vault.FilePath, "Vault Closed", MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.OK);
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
            finally
            {
                if (!vault.isVaultOpen())
                {
                    ClearOpenVault();
                }
            }
        }
        #endregion


        /// <summary>
        /// Set UI to the opened Vault
        /// </summary>
        private void SetOpenVault()
        {
            vaultLabel.Text = "Open Vault: " + vault.FileName;
            vaultLabel.ToolTip = vault.FilePath;
        }
        /// <summary>
        /// Clear UI from the opened vault
        /// </summary>
        private void ClearOpenVault()
        {
            vaultLabel.Foreground = Brushes.DarkRed;

            vaultLabel.Text = "No Vault is open";
            vaultLabel.ToolTip = "Click the Vault menu to create/load a vault";
        }
    }
}
