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
        public MainWindow()
        {
            InitializeComponent();
            Directory.SetCurrentDirectory("../../../Debug");
        }
        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            //open pop-up window for choosing file and encrypting it
            new EncryptionWindow().ShowDialog();
        }

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            new DecryptionWindow().ShowDialog();
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
            new VaultCreationWindow().ShowDialog();
        }
    }
}
