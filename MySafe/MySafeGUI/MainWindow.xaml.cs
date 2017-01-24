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
            vault = new FileVault();
            InitializeComponent();
            Directory.SetCurrentDirectory("../../../Simulation");
        }
        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            if (vault == null)
            {
                MessageBox.Show("There is no open vault at the moment to decrypt with", "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
            try
            {
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
            if(vault == null)
            {
                MessageBox.Show("There is no open vault at the moment to decrypt with", "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
            try
            {
                new DecryptionWindow(vault).ShowDialog();
            }
            catch(Exception error)
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

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                new VaultCreationWindow(vault).ShowDialog();
            }
            catch(Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                vault = null;
            }
            finally
            {
                openVault.Text = (vault == null) ? "There isn't any open vault currently." : "There is a an open vault now.";
            }
        }

        private void MenuItem_Click_1(object sender, RoutedEventArgs e)
        {
            try
            {
                new LoadVaultWindow(vault).ShowDialog();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                vault = null;
            }
            finally
            {
                openVault.Text = (vault == null) ? "There isn't any open vault currently." : "There is a an open vault now.";
            }
        }
    }
}
