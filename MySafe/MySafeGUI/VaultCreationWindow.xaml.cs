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

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for VaultCreationWindow.xaml
    /// </summary>
    public partial class VaultCreationWindow : Window
    {
        public VaultCreationWindow()
        {
            InitializeComponent();
            Directory.SetCurrentDirectory("../../../Debug");
        }

        private void Done_Click(object sender, RoutedEventArgs e)
        {
            MySafe_Adapter.cppToCsharpAdapter.load_valut(new IntPtr(0), VaultName.Text, masterPassword.Text);
            MessageBox.Show("The vault has been created successfully.", "Vault Created", MessageBoxButton.OK, MessageBoxImage.Exclamation, MessageBoxResult.OK);
        }
    }
}
